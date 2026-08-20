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

	// A header block that references an entry the peer has not processed yet
	// leaves the stream BLOCKED until its decoder catches up, and RFC 9204 2.1.2
	// forbids blocking more streams than the peer's
	// SETTINGS_QPACK_BLOCKED_STREAMS allows. Peers differ sharply here: Google
	// advertises 100, Cloudflare offers no dynamic table at all, and a peer that
	// advertises 0 will simply never answer a blocking request -- which is
	// exactly how this failed before the gate existed. When blocking is not
	// allowed we still insert, but only reference entries the peer has
	// acknowledged.
	blocked       uint64            // peer's SETTINGS_QPACK_BLOCKED_STREAMS
	knownReceived uint64            // inserts the peer has acknowledged
	sentRIC       map[uint64]uint64 // stream id -> Required Insert Count of its last block
	streamID      uint64            // stream the next block belongs to
}

// EnableDynamicTable turns on dynamic-table encoding, writing insert
// instructions to encStream. capacity must not exceed the peer's advertised
// SETTINGS_QPACK_MAX_TABLE_CAPACITY. Calling it more than once is a no-op.
func (e *Encoder) EnableDynamicTable(encStream io.Writer, capacity uint64) {
	if e.dyn != nil || encStream == nil || capacity == 0 {
		return
	}
	e.dyn = &encoderDynamic{stream: encStream, capacity: capacity, sentRIC: map[uint64]uint64{}}
}

// SetBlockedStreams records the peer's SETTINGS_QPACK_BLOCKED_STREAMS. Until it
// is called the encoder assumes zero, so it never blocks a stream it has not
// been told it may block.
func (e *Encoder) SetBlockedStreams(n uint64) {
	if e.dyn == nil {
		return
	}
	e.dyn.mu.Lock()
	defer e.dyn.mu.Unlock()
	e.dyn.blocked = n
}

// SetStreamID names the request stream the next header block belongs to, so a
// Section Acknowledgment for it can be matched to the count that block required.
func (e *Encoder) SetStreamID(id uint64) {
	if e.dyn == nil {
		return
	}
	e.dyn.mu.Lock()
	defer e.dyn.mu.Unlock()
	e.dyn.streamID = id
}

// NoteSectionAck records the peer acknowledging a header block: it has processed
// at least as many inserts as that block required.
func (e *Encoder) NoteSectionAck(streamID uint64) {
	if e.dyn == nil {
		return
	}
	d := e.dyn
	d.mu.Lock()
	defer d.mu.Unlock()
	if ric, ok := d.sentRIC[streamID]; ok {
		if ric > d.knownReceived {
			d.knownReceived = ric
		}
		delete(d.sentRIC, streamID)
	}
}

// NoteInsertCountIncrement records the peer processing n further inserts.
func (e *Encoder) NoteInsertCountIncrement(n uint64) {
	if e.dyn == nil {
		return
	}
	e.dyn.mu.Lock()
	defer e.dyn.mu.Unlock()
	e.dyn.knownReceived += n
}

// NoteStreamCancel drops the bookkeeping for a cancelled stream.
func (e *Encoder) NoteStreamCancel(streamID uint64) {
	if e.dyn == nil {
		return
	}
	e.dyn.mu.Lock()
	defer e.dyn.mu.Unlock()
	delete(e.dyn.sentRIC, streamID)
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
	// Chrome reaches for the static table's NAME when it has one -- an "Insert
	// With Name Reference" is shorter than repeating the name, and its encoder
	// stream shows both forms side by side: name references for user-agent,
	// accept, accept-encoding and friends, literal names for sec-ch-ua*,
	// sec-fetch-*, priority and x-*. Inserting everything literally, as this
	// used to, is a visible difference on the encoder stream.
	if idx, ok := staticNameIndex(hf.Name); ok {
		// Insert With Name Reference: 1Txxxxxx, T=1 for the static table,
		// 6-bit prefix index.
		off := len(b)
		b = appendVarInt(b, 6, uint64(idx))
		b[off] |= 0x80 | 0x40
	} else {
		// Insert With Literal Name: 01Hxxxxx (H = Huffman) with a 5-bit name length.
		off := len(b)
		b = appendVarInt(b, 5, hpack.HuffmanEncodeLength(hf.Name))
		b[off] |= 0x40 | 0x20 // pattern 01, Huffman
		b = hpack.AppendHuffmanString(b, hf.Name)
	}
	off := len(b)
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

// staticNameIndex returns a static-table index whose entry has this name.
func staticNameIndex(name string) (uint8, bool) {
	e, ok := encoderMap[name]
	if !ok {
		return 0, false
	}
	// idx is the index of the entry that carries this name; entries that also
	// pin specific values are irrelevant here, since only the name is referenced.
	return e.idx, true
}

// shouldInsert reports whether a field is worth putting in the dynamic table.
// Browsers insert the stable, repeated request headers and leave one-offs
// literal; never insert a cookie (it changes per request and would thrash).
func shouldInsert(hf HeaderField) bool {
	if len(hf.Name) == 0 {
		return false
	}
	if hf.Name[0] == ':' {
		// :method and :scheme have exact static-table entries, so inserting them
		// would be pointless. :authority and :path only have their names there,
		// and Chrome does insert both -- its encoder stream references static
		// indices 0 and 1 for exactly that.
		return hf.Name == ":authority" || hf.Name == ":path"
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
	// mayReference reports whether referencing an entry is allowed right now.
	// With no blocking budget, only entries the peer has already acknowledged
	// can be referenced; the rest are inserted for later requests and sent
	// literally in this one.
	mayReference := func(abs uint64) bool {
		return d.blocked > 0 || abs < d.knownReceived
	}

	refs := make([]ref, 0, len(e.pending))
	var maxAbs uint64
	var used bool
	for _, hf := range e.pending {
		if abs, ok := d.find(hf); ok && mayReference(abs) {
			refs = append(refs, ref{abs: abs, dynamic: true, hf: hf})
			if abs+1 > maxAbs {
				maxAbs = abs + 1
			}
			used = true
			continue
		} else if ok {
			refs = append(refs, ref{hf: hf}) // known, but not yet acknowledged
			continue
		}
		if shouldInsert(hf) {
			if abs, ok := d.insert(hf); ok {
				if mayReference(abs) {
					refs = append(refs, ref{abs: abs, dynamic: true, hf: hf})
					if abs+1 > maxAbs {
						maxAbs = abs + 1
					}
					used = true
					continue
				}
				// Inserted for a later request; this block stays literal so it
				// does not block on an entry the peer has not processed.
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
		// Remember what this block required, so the peer's Section
		// Acknowledgment for this stream tells us it has processed that much.
		d.sentRIC[d.streamID] = maxAbs
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
