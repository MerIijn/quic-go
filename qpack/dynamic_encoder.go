package qpack

import (
	"io"
	"sync"

	"golang.org/x/net/http2/hpack"
)

// Request-side QPACK dynamic-table ENCODING (RFC 9204 §4.3, §4.5).
//
// Upstream quic-go/qpack encodes every header block with Required Insert Count 0
// using only the static table and literals, and never writes anything to the
// QPACK encoder stream. Browsers do the opposite: they advertise a dynamic table
// AND use it, inserting header fields on the encoder stream and referencing them
// from subsequent header blocks. Advertising a 64 KB table and never touching it
// is an asymmetry no browser exhibits, so this file adds the encoder side.

// encoderDynamic holds the encoder's view of its own dynamic table — i.e. what
// we have told the peer to insert. It mirrors the peer's decoder table.
type encoderDynamic struct {
	mu        sync.Mutex
	stream    io.Writer // the QPACK encoder unidirectional stream
	capacity  uint64
	sentCap   bool
	size      uint64
	insertCnt uint64        // absolute index of the next insertion
	entries   []HeaderField // entries[i] has absolute index dropped+i
	dropped   uint64
}

// EnableDynamicTable turns on dynamic-table encoding, writing insert
// instructions to encStream. capacity must not exceed the peer's advertised
// SETTINGS_QPACK_MAX_TABLE_CAPACITY. Calling it more than once is a no-op.
func (e *Encoder) EnableDynamicTable(encStream io.Writer, capacity uint64) {
	if e.dyn != nil || encStream == nil || capacity == 0 {
		return
	}
	e.dyn = &encoderDynamic{stream: encStream, capacity: capacity}
}

// find returns the absolute index of an exact name+value match, if present.
func (d *encoderDynamic) find(hf HeaderField) (uint64, bool) {
	for i, e := range d.entries {
		if e.Name == hf.Name && e.Value == hf.Value {
			return d.dropped + uint64(i), true
		}
	}
	return 0, false
}

// insert writes an "Insert With Literal Name" instruction to the encoder stream
// and records the entry, returning its absolute index.
func (d *encoderDynamic) insert(hf HeaderField) (uint64, bool) {
	sz := uint64(len(hf.Name)+len(hf.Value)) + entryOverhead
	if sz > d.capacity {
		return 0, false
	}
	var b []byte
	if !d.sentCap {
		// Set Dynamic Table Capacity: 001xxxxx with a 5-bit prefix.
		b = appendVarInt(b, 5, d.capacity)
		b[0] |= 0x20
		d.sentCap = true
	}
	// Insert With Literal Name: 01Hxxxxx (H = Huffman) with a 5-bit name length.
	off := len(b)
	b = appendVarInt(b, 5, hpack.HuffmanEncodeLength(hf.Name))
	b[off] |= 0x40 | 0x20 // pattern 01, Huffman
	b = hpack.AppendHuffmanString(b, hf.Name)
	off = len(b)
	b = appendVarInt(b, 7, hpack.HuffmanEncodeLength(hf.Value))
	b[off] |= 0x80 // Huffman
	b = hpack.AppendHuffmanString(b, hf.Value)

	if _, err := d.stream.Write(b); err != nil {
		return 0, false
	}
	// Evict from the front until the new entry fits.
	for len(d.entries) > 0 && d.size+sz > d.capacity {
		ev := d.entries[0]
		d.entries = d.entries[1:]
		d.size -= uint64(len(ev.Name)+len(ev.Value)) + entryOverhead
		d.dropped++
	}
	d.entries = append(d.entries, hf)
	d.size += sz
	idx := d.insertCnt
	d.insertCnt++
	return idx, true
}

// shouldInsert reports whether a field is worth putting in the dynamic table.
// Browsers insert the stable, repeated request headers and leave one-offs
// literal; never insert a cookie (it changes per request and would thrash).
func shouldInsert(hf HeaderField) bool {
	if len(hf.Name) == 0 || hf.Name[0] == ':' {
		return false // pseudo-headers stay static/literal
	}
	switch hf.Name {
	case "cookie", "content-length", "if-none-match", "if-modified-since", "referer":
		return false
	}
	return len(hf.Name)+len(hf.Value) <= 512
}

// flushDynamic encodes the buffered fields using the dynamic table and writes the
// complete header block (prefix + field lines) to the encoder's writer.
func (e *Encoder) flushDynamic() error {
	d := e.dyn
	d.mu.Lock()
	defer d.mu.Unlock()

	type ref struct {
		abs     uint64
		dynamic bool
		hf      HeaderField
	}
	refs := make([]ref, 0, len(e.pending))
	var maxAbs uint64
	var used bool
	for _, hf := range e.pending {
		if abs, ok := d.find(hf); ok {
			refs = append(refs, ref{abs: abs, dynamic: true, hf: hf})
			if abs+1 > maxAbs {
				maxAbs = abs + 1
			}
			used = true
			continue
		}
		if shouldInsert(hf) {
			if abs, ok := d.insert(hf); ok {
				refs = append(refs, ref{abs: abs, dynamic: true, hf: hf})
				if abs+1 > maxAbs {
					maxAbs = abs + 1
				}
				used = true
				continue
			}
		}
		refs = append(refs, ref{hf: hf})
	}

	// Header Block Prefix (RFC 9204 §4.5.1). Required Insert Count is encoded
	// modulo 2*MaxEntries; Base == RIC gives DeltaBase 0 with the sign bit clear.
	var out []byte
	if !used {
		out = appendVarInt(out, 8, 0)
		out = appendVarInt(out, 7, 0)
	} else {
		maxEntries := d.capacity / entryOverhead
		enc := uint64(0)
		if maxEntries > 0 {
			enc = maxAbs%(2*maxEntries) + 1
		}
		out = appendVarInt(out, 8, enc)
		out = appendVarInt(out, 7, 0) // DeltaBase 0, S=0 → Base == RIC
	}

	for _, r := range refs {
		if r.dynamic {
			// Indexed Field Line, dynamic (T=0): 1 0 index(6+), relative to Base.
			off := len(out)
			out = appendVarInt(out, 6, maxAbs-1-r.abs)
			out[off] |= 0x80
			continue
		}
		out = e.appendStaticOrLiteral(out, r.hf)
	}
	_, err := e.w.Write(out)
	return err
}

// appendStaticOrLiteral encodes one field without the dynamic table, reusing the
// static table when it has the name (and value).
func (e *Encoder) appendStaticOrLiteral(out []byte, f HeaderField) []byte {
	saved := e.buf
	e.buf = out
	if idxAndVals, nameFound := encoderMap[f.Name]; nameFound {
		if idxAndVals.values == nil {
			if len(f.Value) == 0 {
				e.writeIndexedField(idxAndVals.idx)
			} else {
				e.writeLiteralFieldWithNameReference(&f, idxAndVals.idx)
			}
		} else if valIdx, valueFound := idxAndVals.values[f.Value]; valueFound {
			e.writeIndexedField(valIdx)
		} else {
			e.writeLiteralFieldWithNameReference(&f, idxAndVals.idx)
		}
	} else {
		e.writeLiteralFieldWithoutNameReference(f)
	}
	out = e.buf
	e.buf = saved
	return out
}
