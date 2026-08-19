package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"
	"sync/atomic"

	"github.com/MerIijn/quic-go"
	"github.com/MerIijn/quic-go/http3/qlog"
	"github.com/MerIijn/quic-go/qlogwriter"
	"github.com/MerIijn/quic-go/qpack"
	"github.com/MerIijn/quic-go/quicvarint"
)

const maxQuarterStreamID = 1<<60 - 1

// invalidStreamID is a stream ID that is invalid. The first valid stream ID in QUIC is 0.
const invalidStreamID = quic.StreamID(-1)

// rawConn is an HTTP/3 connection.
// It provides HTTP/3 specific functionality by wrapping a quic.Conn,
// in particular handling of unidirectional HTTP/3 streams, SETTINGS and datagrams.
type rawConn struct {
	conn *quic.Conn

	logger *slog.Logger

	enableDatagrams bool

	streamMx sync.Mutex
	streams  map[quic.StreamID]*stateTrackingStream

	rcvdControlStr         atomic.Bool
	rcvdQPACKEncoderStr    atomic.Bool
	rcvdQPACKDecoderStr    atomic.Bool
	controlStrHandler      func(*quic.ReceiveStream, *frameParser) // is called *after* the SETTINGS frame was parsed
	qpackEncoderStrHandler func(*quic.ReceiveStream)               // reads the peer's QPACK encoder stream (dynamic table)
	qpackDecoderStrHandler func(*quic.ReceiveStream)               // reads the peer's QPACK decoder stream (acknowledgements)

	// QPACK encoder/decoder unidirectional streams. Real browsers open both right
	// after the control stream even when they never use the QPACK dynamic table.
	// They carry only their 1-byte stream type and are kept open for the life of
	// the connection — closing a QPACK stream is an H3_CLOSED_CRITICAL_STREAM
	// connection error (RFC 9204 §4.2), so these references just pin them alive.
	qpackEncStr *quic.SendStream
	qpackDecStr *quic.SendStream
	qpackDecMx  sync.Mutex // serializes decoder- and encoder-stream writes
	// The stream type varints are written on first use, not at open time.
	qpackDecTypeSent bool
	qpackEncTypeSent bool

	// controlStr is our local control stream; browsers send PRIORITY_UPDATE frames
	// on it per request. controlMx guards writes after the initial SETTINGS frame.
	controlStr *quic.SendStream
	controlMx  sync.Mutex

	onStreamsEmpty func()

	settings         *Settings
	receivedSettings chan struct{}

	qlogger   qlogwriter.Recorder
	qloggerWG sync.WaitGroup // tracks goroutines that may produce qlog events
}

func newRawConn(
	quicConn *quic.Conn,
	enableDatagrams bool,
	onStreamsEmpty func(),
	controlStrHandler func(*quic.ReceiveStream, *frameParser),
	qlogger qlogwriter.Recorder,
	logger *slog.Logger,
) *rawConn {
	c := &rawConn{
		conn:              quicConn,
		logger:            logger,
		enableDatagrams:   enableDatagrams,
		receivedSettings:  make(chan struct{}),
		streams:           make(map[quic.StreamID]*stateTrackingStream),
		qlogger:           qlogger,
		onStreamsEmpty:    onStreamsEmpty,
		controlStrHandler: controlStrHandler,
	}
	if qlogger != nil {
		context.AfterFunc(quicConn.Context(), c.closeQlogger)
	}
	return c
}

func (c *rawConn) OpenUniStream() (*quic.SendStream, error) {
	return c.conn.OpenUniStream()
}

// openControlStream opens the control stream and sends the SETTINGS frame.
// It returns the control stream (needed by the server for sending GOAWAY later).
func (c *rawConn) openControlStream(settings *settingsFrame) (*quic.SendStream, error) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	str, err := c.conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	b = settings.Append(b)
	// A browser follows SETTINGS with a reserved (GREASE) frame on the control
	// stream, in the same write. Only do it in the fingerprint path (ordered
	// settings); default quic-go behaviour is unchanged.
	if settings.Ordered != nil {
		b = appendGREASEFrame(b)
	}
	if c.qlogger != nil {
		sf := qlog.SettingsFrame{
			MaxFieldSectionSize: settings.MaxFieldSectionSize,
			Other:               maps.Clone(settings.Other),
		}
		if settings.Datagram {
			sf.Datagram = pointer(true)
		}
		if settings.ExtendedConnect {
			sf.ExtendedConnect = pointer(true)
		}
		// An ordered SETTINGS frame is written verbatim and bypasses the fields
		// above, so log what actually goes on the wire rather than the unused
		// struct defaults — otherwise the trace shows an empty frame.
		if settings.Ordered != nil {
			sf = qlog.SettingsFrame{MaxFieldSectionSize: -1, Other: map[uint64]uint64{}}
			for _, s := range settings.Ordered {
				switch s.ID {
				case settingMaxFieldSectionSize:
					sf.MaxFieldSectionSize = int64(s.Val)
				case settingDatagram:
					sf.Datagram = pointer(s.Val == 1)
				case settingExtendedConnect:
					sf.ExtendedConnect = pointer(s.Val == 1)
				default:
					sf.Other[s.ID] = s.Val
				}
			}
		}
		c.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: str.StreamID(),
			Raw:      qlog.RawInfo{Length: len(b)},
			Frame:    qlog.Frame{Frame: sf},
		})
	}
	if _, err := str.Write(b); err != nil {
		return nil, err
	}
	c.controlStr = str
	return str, nil
}

// sendPriorityUpdate writes an HTTP/3 PRIORITY_UPDATE frame (type 0xF0700, for a
// request stream) on the control stream — matching Chrome, which sends one per
// request with the request's priority (e.g. "u=0, i" for the main navigation).
// Best-effort: a failure here must not fail the request.
func (c *rawConn) sendPriorityUpdate(streamID quic.StreamID, priority string) {
	c.controlMx.Lock()
	defer c.controlMx.Unlock()
	if c.controlStr == nil {
		return
	}
	payload := quicvarint.Append(nil, uint64(streamID))
	payload = append(payload, []byte(priority)...)
	b := quicvarint.Append(nil, 0xf0700)
	b = quicvarint.Append(b, uint64(len(payload)))
	b = append(b, payload...)
	c.controlStr.Write(b)
}

// openQPACKStreams reserves the client's QPACK decoder and encoder
// unidirectional streams. It deliberately writes NOTHING on them, not even the
// stream-type varint: QUICHE reserves both stream ids at session start but only
// writes the type byte when it has an instruction to send, and a capture of
// Chrome 150 that never needed one shows no such streams on the wire at all
// (while one that did shows both). Writing the types eagerly would put two
// extra streams in our first flight that a browser's does not have.
//
// Order matters: the ids are assigned in open order, and Chrome's are control
// (2), QPACK decoder (6), QPACK encoder (10) -- so open decoder before encoder.
// The streams are never closed (see the qpackEncStr/qpackDecStr comment).
func (c *rawConn) openQPACKStreams() error {
	dec, err := c.conn.OpenUniStream()
	if err != nil {
		return err
	}
	enc, err := c.conn.OpenUniStream()
	if err != nil {
		return err
	}
	c.qpackDecStr = dec
	c.qpackEncStr = enc
	return nil
}

// writeQPACKDecoder writes an instruction on the decoder stream, prefixing the
// stream type on the first write (see openQPACKStreams). The caller holds
// qpackDecMx.
func (c *rawConn) writeQPACKDecoder(b []byte) {
	if c.qpackDecStr == nil {
		return
	}
	if !c.qpackDecTypeSent {
		b = append(quicvarint.Append(nil, streamTypeQPACKDecoderStream), b...)
		c.qpackDecTypeSent = true
	}
	_, _ = c.qpackDecStr.Write(b)
}

// QPACKEncoderStream returns the encoder stream with its type varint already
// written, opening that write lazily the same way the decoder stream does.
func (c *rawConn) QPACKEncoderStream() *quic.SendStream {
	c.qpackDecMx.Lock()
	defer c.qpackDecMx.Unlock()
	if c.qpackEncStr == nil {
		return nil
	}
	if !c.qpackEncTypeSent {
		c.qpackEncTypeSent = true
		_, _ = c.qpackEncStr.Write(quicvarint.Append(nil, streamTypeQPACKEncoderStream))
	}
	return c.qpackEncStr
}

func (c *rawConn) qpackSectionAck(id quic.StreamID) {
	c.qpackDecMx.Lock()
	defer c.qpackDecMx.Unlock()
	// 1xxxxxxx: stream id as a 7-bit prefixed integer.
	c.writeQPACKDecoder(qpack.AppendPrefixedInt(nil, 0x80, 7, uint64(id)))
}

// qpackInsertCountIncrement writes an Insert Count Increment (RFC 9204 4.4.3)
// covering inserts that no Section Acknowledgment has already acknowledged.
func (c *rawConn) qpackInsertCountIncrement(n uint64) {
	if n == 0 {
		return
	}
	c.qpackDecMx.Lock()
	defer c.qpackDecMx.Unlock()
	// 00xxxxxx: increment as a 6-bit prefixed integer.
	c.writeQPACKDecoder(qpack.AppendPrefixedInt(nil, 0x00, 6, n))
}

func (c *rawConn) TrackStream(str *quic.Stream) *stateTrackingStream {
	hstr := newStateTrackingStream(str, c, func(b []byte) error { return c.sendDatagram(str.StreamID(), b) })

	c.streamMx.Lock()
	c.streams[str.StreamID()] = hstr
	c.qloggerWG.Add(1)
	c.streamMx.Unlock()
	return hstr
}

func (c *rawConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *rawConn) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *rawConn) clearStream(id quic.StreamID) {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	if _, ok := c.streams[id]; ok {
		delete(c.streams, id)
		c.qloggerWG.Done()
	}
	if len(c.streams) == 0 {
		c.onStreamsEmpty()
	}
}

func (c *rawConn) hasActiveStreams() bool {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	return len(c.streams) > 0
}

func (c *rawConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	return c.conn.CloseWithError(code, msg)
}

func (c *rawConn) handleUnidirectionalStream(str *quic.ReceiveStream, isServer bool) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	streamType, err := quicvarint.Read(quicvarint.NewReader(str))
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
		}
		return
	}
	// We're only interested in the control stream here.
	switch streamType {
	case streamTypeControlStream:
	case streamTypeQPACKEncoderStream:
		if isFirst := c.rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
		}
		// Feed the peer's QPACK encoder instructions into our dynamic table so
		// dynamic-table-encoded responses decode. When no handler is set we fall
		// back to draining/ignoring the stream (static-only).
		if c.qpackEncoderStrHandler != nil {
			c.qpackEncoderStrHandler(str)
		}
		return
	case streamTypeQPACKDecoderStream:
		if isFirst := c.rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
		}
		// Read the peer's acknowledgements when we encode with the dynamic
		// table; otherwise drain and ignore.
		if c.qpackDecoderStrHandler != nil {
			c.qpackDecoderStrHandler(str)
		}
		return
	case streamTypePushStream:
		if isServer {
			// only the server can push
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
		} else {
			// we never increased the Push ID, so we don't expect any push streams
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
		}
		return
	default:
		str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
		return
	}
	// Only a single control stream is allowed.
	if isFirstControlStr := c.rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
		return
	}
	c.handleControlStream(str)
}

func (c *rawConn) handleControlStream(str *quic.ReceiveStream) {
	fp := &frameParser{closeConn: c.conn.CloseWithError, r: str, streamID: str.StreamID()}
	f, err := fp.ParseNext(c.qlogger)
	if err != nil {
		var serr *quic.StreamError
		if err == io.EOF || errors.As(err, &serr) {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
			return
		}
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
		return
	}
	sf, ok := f.(*settingsFrame)
	if !ok {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
		return
	}
	c.settings = &Settings{
		EnableDatagrams:       sf.Datagram,
		EnableExtendedConnect: sf.ExtendedConnect,
		Other:                 sf.Other,
	}
	close(c.receivedSettings)
	if sf.Datagram {
		// If datagram support was enabled on our side as well as on the server side,
		// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
		// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
		if c.enableDatagrams && !c.ConnectionState().SupportsDatagrams.Remote {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
			return
		}
		c.qloggerWG.Go(func() {
			if err := c.receiveDatagrams(); err != nil {
				if c.logger != nil {
					c.logger.Debug("receiving datagrams failed", "error", err)
				}
			}
		})
	}

	if c.controlStrHandler != nil {
		c.controlStrHandler(str, fp)
	}
}

func (c *rawConn) sendDatagram(streamID quic.StreamID, b []byte) error {
	// TODO: this creates a lot of garbage and an additional copy
	data := make([]byte, 0, len(b)+8)
	quarterStreamID := uint64(streamID / 4)
	data = quicvarint.Append(data, uint64(streamID/4))
	data = append(data, b...)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuarterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(data),
				PayloadLength: len(b),
			},
		})
	}
	return c.conn.SendDatagram(data)
}

func (c *rawConn) receiveDatagrams() error {
	for {
		b, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		quarterStreamID, n, err := quicvarint.Parse(b)
		if err != nil {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("could not read quarter stream id: %w", err)
		}
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.DatagramParsed{
				QuarterStreamID: quarterStreamID,
				Raw: qlog.RawInfo{
					Length:        len(b),
					PayloadLength: len(b) - n,
				},
			})
		}
		if quarterStreamID > maxQuarterStreamID {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("invalid quarter stream id: %w", err)
		}
		streamID := quic.StreamID(4 * quarterStreamID)
		c.streamMx.Lock()
		dg, ok := c.streams[streamID]
		c.streamMx.Unlock()
		if !ok {
			continue
		}
		dg.enqueueDatagram(b[n:])
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
// Settings can be optained from the Settings method after the channel was closed.
func (c *rawConn) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *rawConn) Settings() *Settings { return c.settings }

// closeQlogger waits for all goroutines that may produce qlog events to finish,
// then closes the qlogger.
func (c *rawConn) closeQlogger() {
	if c.qlogger == nil {
		return
	}
	c.qloggerWG.Wait()
	c.qlogger.Close()
}
