package http3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/idna"

	"github.com/MerIijn/quic-go"
	"github.com/MerIijn/quic-go/http3/qlog"
	"github.com/MerIijn/quic-go/qlogwriter"
	"github.com/MerIijn/quic-go/qpack"
)

const bodyCopyBufferSize = 8 * 1024

type requestWriter struct {
	mutex     sync.Mutex
	encoder   *qpack.Encoder
	headerBuf *bytes.Buffer

	// pseudoHeaderOrder / headerOrder are the default request header ordering
	// (browser fingerprint). A per-request PHeader-Order / Header-Order header
	// overrides them. See enumerateHeaders in encodeHeaders.
	pseudoHeaderOrder []string
	headerOrder       []string
}

// defaultPseudoHeaderOrder is Chrome's request pseudo-header order, used when the
// Transport sets none. RFC 9114 permits any order; matching Chrome avoids a tell.
var defaultPseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}

// Control headers consumed for ordering and never emitted on the wire (they
// mirror the sibling net/http2 fork's Header-Order / PHeader-Order mechanism).
const (
	headerOrderKey       = "Header-Order"
	pseudoHeaderOrderKey = "PHeader-Order"
)

func newRequestWriter() *requestWriter {
	headerBuf := &bytes.Buffer{}
	encoder := qpack.NewEncoder(headerBuf)
	return &requestWriter{
		encoder:           encoder,
		headerBuf:         headerBuf,
		pseudoHeaderOrder: defaultPseudoHeaderOrder,
	}
}

// enableDynamicQPACK switches the shared encoder to dynamic-table mode, writing
// insertions to the QPACK encoder stream. Guarded by the same mutex writeHeaders
// takes, so it can't race with an in-flight request.
func (w *requestWriter) enableDynamicQPACK(encStream io.Writer, capacity uint64) {
	if encStream == nil || capacity == 0 {
		return
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.encoder.EnableDynamicTable(encStream, capacity)
}

func (w *requestWriter) WriteRequestHeader(wr io.Writer, req *http.Request, gzip bool, streamID quic.StreamID, qlogger qlogwriter.Recorder) error {
	buf := &bytes.Buffer{}
	if err := w.writeHeaders(buf, req, gzip, streamID, qlogger); err != nil {
		return err
	}
	if _, err := wr.Write(buf.Bytes()); err != nil {
		return err
	}
	trace := httptrace.ContextClientTrace(req.Context())
	traceWroteHeaders(trace)
	return nil
}

func (w *requestWriter) writeHeaders(wr io.Writer, req *http.Request, gzip bool, streamID quic.StreamID, qlogger qlogwriter.Recorder) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	defer w.encoder.Close()
	defer w.headerBuf.Reset()

	var trailers string
	if len(req.Trailer) > 0 {
		keys := make([]string, 0, len(req.Trailer))
		for k := range req.Trailer {
			if httpguts.ValidTrailerHeader(k) {
				keys = append(keys, k)
			}
		}
		trailers = strings.Join(keys, ", ")
	}

	headerFields, err := w.encodeHeaders(req, gzip, trailers, actualContentLength(req), qlogger != nil)
	if err != nil {
		return err
	}
	// Completes the block. In QPACK dynamic-table mode the fields were buffered
	// (the prefix carries the Required Insert Count, so it can only be written
	// once every field is known); this emits the encoder-stream insertions and
	// the encoded block. It is a no-op for the static-only encoder.
	if err := w.encoder.Flush(); err != nil {
		return err
	}

	b := make([]byte, 0, 128)
	b = (&headersFrame{Length: uint64(w.headerBuf.Len())}).Append(b)
	if qlogger != nil {
		qlogCreatedHeadersFrame(qlogger, streamID, len(b)+w.headerBuf.Len(), w.headerBuf.Len(), headerFields)
	}
	if _, err := wr.Write(b); err != nil {
		return err
	}
	_, err = wr.Write(w.headerBuf.Bytes())
	return err
}

func isExtendedConnectRequest(req *http.Request) bool {
	return req.Method == http.MethodConnect && req.Proto != "" && req.Proto != "HTTP/1.1"
}

// copied from net/transport.go
// Modified to support Extended CONNECT:
// Contrary to what the godoc for the http.Request says,
// we do respect the Proto field if the method is CONNECT.
//
// The returned header fields are only set if doQlog is true.
func (w *requestWriter) encodeHeaders(req *http.Request, addGzipHeader bool, trailers string, contentLength int64, doQlog bool) ([]qlog.HeaderField, error) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return nil, err
	}
	if !httpguts.ValidHostHeader(host) {
		return nil, errors.New("http3: invalid Host header")
	}

	// http.NewRequest sets this field to HTTP/1.1
	isExtendedConnect := isExtendedConnectRequest(req)
	if isExtendedConnect && !validExtendedConnectProtocol(req.Proto) {
		return nil, fmt.Errorf("invalid request :protocol %q", req.Proto)
	}

	var path string
	if req.Method != http.MethodConnect || isExtendedConnect {
		path = req.URL.RequestURI()
		if !validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return nil, fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				} else {
					return nil, fmt.Errorf("invalid request :path %q", orig)
				}
			}
		}
	}

	// Check for any invalid headers and return an error before we
	// potentially pollute our hpack state. (We want to be able to
	// continue to reuse the hpack encoder for future requests)
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("invalid HTTP header name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("invalid HTTP header value %q for header %q", v, k)
			}
		}
	}

	// Effective ordering: a per-request PHeader-Order / Header-Order header
	// overrides the writer's (browser-profile) defaults. These control headers
	// are consumed here and never emitted on the wire (see emitField).
	pseudoOrder := w.pseudoHeaderOrder
	if v := req.Header[pseudoHeaderOrderKey]; len(v) > 0 {
		pseudoOrder = v
	}
	headerOrder := w.headerOrder
	if v := req.Header[headerOrderKey]; len(v) > 0 {
		headerOrder = v
	}

	enumerateHeaders := func(f func(name, value string)) {
		// 8.1.2.3 Request Pseudo-Header Fields
		// The :path pseudo-header field includes the path and query parts of the
		// target URI (the path-absolute production and optionally a '?' character
		// followed by the query production (see Sections 3.3 and 3.4 of
		// [RFC3986]).
		type pseudoKV struct{ k, v string }
		pseudos := []pseudoKV{{":authority", host}, {":method", req.Method}}
		if req.Method != http.MethodConnect || isExtendedConnect {
			pseudos = append(pseudos, pseudoKV{":path", path}, pseudoKV{":scheme", req.URL.Scheme})
		}
		if isExtendedConnect {
			pseudos = append(pseudos, pseudoKV{":protocol", req.Proto})
		}
		if len(pseudoOrder) > 0 {
			done := make(map[string]bool, len(pseudos))
			for _, name := range pseudoOrder {
				for _, p := range pseudos {
					if p.k == name && !done[p.k] {
						f(p.k, p.v)
						done[p.k] = true
					}
				}
			}
			for _, p := range pseudos { // any not covered by the order
				if !done[p.k] {
					f(p.k, p.v)
				}
			}
		} else {
			for _, p := range pseudos {
				f(p.k, p.v)
			}
		}
		if trailers != "" {
			f("trailer", trailers)
		}

		var didUA bool
		// emitField applies the per-header rules (skip Host/Content-Length and the
		// connection-specific + ordering-control headers, dedup User-Agent, split
		// Cookie per RFC 9113 §8.1.2.5) to a single header key.
		emitField := func(k string, vv []string) {
			if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
				// Host is :authority, already sent.
				// Content-Length is automatic, set below.
				return
			} else if strings.EqualFold(k, headerOrderKey) || strings.EqualFold(k, pseudoHeaderOrderKey) {
				// Ordering-control headers: consumed above, never on the wire.
				return
			} else if strings.EqualFold(k, "connection") || strings.EqualFold(k, "proxy-connection") ||
				strings.EqualFold(k, "transfer-encoding") || strings.EqualFold(k, "upgrade") ||
				strings.EqualFold(k, "keep-alive") {
				// Per 8.1.2.2 Connection-Specific Header Fields, don't send
				// connection-specific fields.
				return
			} else if strings.EqualFold(k, "user-agent") {
				// Match Go's http1 behavior: at most one User-Agent. If set to nil
				// or empty string, omit it; otherwise if not mentioned include the
				// default (below).
				didUA = true
				if len(vv) < 1 {
					return
				}
				vv = vv[:1]
				if vv[0] == "" {
					return
				}
			} else if strings.EqualFold(k, "cookie") {
				// Per 8.1.2.5, the Cookie header MAY be split into separate fields
				// for better compression. Browsers split on "; ".
				for _, v := range vv {
					for {
						p := strings.IndexByte(v, ';')
						if p < 0 {
							break
						}
						f("cookie", v[:p])
						p++
						for p+1 <= len(v) && v[p] == ' ' {
							p++
						}
						v = v[p:]
					}
					if len(v) > 0 {
						f("cookie", v)
					}
				}
				return
			}

			for _, v := range vv {
				f(k, v)
			}
		}

		// content-length is computed automatically, so it never appears in
		// req.Header and the ordering loop can't place it. Honor the slot the
		// caller gave "content-length" in Header-Order; otherwise trail (stdlib
		// default).
		sendCL := shouldSendReqContentLength(req.Method, contentLength)
		clEmitted := false
		emitContentLength := func() {
			if sendCL && !clEmitted {
				f("content-length", strconv.FormatInt(contentLength, 10))
				clEmitted = true
			}
		}

		if len(headerOrder) > 0 {
			// Emit regular headers in the caller's order (case-insensitive), then
			// any remaining headers in map order.
			done := make(map[string]bool, len(req.Header))
			for _, name := range headerOrder {
				if strings.EqualFold(name, "content-length") {
					emitContentLength()
					continue
				}
				for k, vv := range req.Header {
					if !done[k] && strings.EqualFold(k, name) {
						emitField(k, vv)
						done[k] = true
					}
				}
			}
			for k, vv := range req.Header {
				if !done[k] {
					emitField(k, vv)
				}
			}
		} else {
			for k, vv := range req.Header {
				emitField(k, vv)
			}
		}
		emitContentLength() // trailing fallback when not placed via Header-Order
		if addGzipHeader {
			f("accept-encoding", "gzip")
		}
		if !didUA {
			f("user-agent", defaultUserAgent)
		}
	}

	// Do a first pass over the headers counting bytes to ensure
	// we don't exceed cc.peerMaxHeaderListSize. This is done as a
	// separate pass before encoding the headers to prevent
	// modifying the hpack state.
	hlSize := uint64(0)
	enumerateHeaders(func(name, value string) {
		hf := hpack.HeaderField{Name: name, Value: value}
		hlSize += uint64(hf.Size())
	})

	// TODO: check maximum header list size
	// if hlSize > cc.peerMaxHeaderListSize {
	// 	return errRequestHeaderListSize
	// }

	trace := httptrace.ContextClientTrace(req.Context())
	traceHeaders := traceHasWroteHeaderField(trace)

	// Header list size is ok. Write the headers.
	var headerFields []qlog.HeaderField
	if doQlog {
		headerFields = make([]qlog.HeaderField, 0, len(req.Header))
	}
	enumerateHeaders(func(name, value string) {
		name = strings.ToLower(name)
		w.encoder.WriteField(qpack.HeaderField{Name: name, Value: value})
		if traceHeaders {
			traceWroteHeaderField(trace, name, value)
		}
		if doQlog {
			headerFields = append(headerFields, qlog.HeaderField{Name: name, Value: value})
		}
	})

	return headerFields, nil
}

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func authorityAddr(authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

// validPseudoPath reports whether v is a valid :path pseudo-header
// value. It must be either:
//
//	*) a non-empty string starting with '/'
//	*) the string '*', for OPTIONS requests.
//
// For now this is only used a quick check for deciding when to clean
// up Opaque URLs before sending requests from the Transport.
// See golang.org/issue/16847
//
// We used to enforce that the path also didn't start with "//", but
// Google's GFE accepts such paths and Chrome sends them, so ignore
// that part of the spec. See golang.org/issue/19103.
func validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

// actualContentLength returns a sanitized version of
// req.ContentLength, where 0 actually means zero (not unknown) and -1
// means unknown.
func actualContentLength(req *http.Request) int64 {
	if req.Body == nil {
		return 0
	}
	if req.ContentLength != 0 {
		return req.ContentLength
	}
	return -1
}

// shouldSendReqContentLength reports whether the http2.Transport should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// WriteRequestTrailer writes HTTP trailers to the stream.
// It should be called after the request body has been fully written.
func (w *requestWriter) WriteRequestTrailer(wr io.Writer, req *http.Request, streamID quic.StreamID, qlogger qlogwriter.Recorder) error {
	_, err := writeTrailers(wr, req.Trailer, streamID, qlogger)
	return err
}
