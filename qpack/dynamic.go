package qpack

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
)

// waitTimeout bounds how long a header block will wait for the dynamic-table
// inserts it references before giving up (and failing to decode) rather than
// hanging the request.
const waitTimeout = 5 * time.Second

// This file adds QPACK dynamic-table support (RFC 9204) to the decoder, which
// upstream quic-go/qpack does not implement. It lets a client advertise a
// non-zero SETTINGS_QPACK_MAX_TABLE_CAPACITY / QPACK_BLOCKED_STREAMS (as real
// browsers do) and still decode responses a server encodes against the dynamic
// table. Only the DECODER side is implemented (reading the peer's encoder
// stream and resolving dynamic references); our own request encoder stays
// static+literal, which is always valid.

// entryOverhead is the per-entry size accounting overhead (RFC 9204 §3.2.1).
const entryOverhead = 32

// DynamicTable is a QPACK decoder dynamic table. It is safe for concurrent use:
// the peer's encoder stream is read on its own goroutine and applied here while
// request/response streams resolve references against it.
type DynamicTable struct {
	mu   sync.Mutex
	cond *sync.Cond

	maxCapacity uint64 // SETTINGS_QPACK_MAX_TABLE_CAPACITY we advertised
	capacity    uint64 // current capacity (set via the encoder stream)
	size        uint64 // current total size in bytes
	closed      bool   // the peer's encoder stream ended; no more inserts will arrive
	timedOut    bool   // a waiter gave up waiting for inserts

	entries     []HeaderField // newest last; entries[len-1] has absolute index insertCount-1
	insertCount uint64        // total entries ever inserted (absolute index base)
	dropped     uint64        // evicted entries; absolute index of entries[0] == dropped
}

// NewDynamicTable creates a dynamic table bounded by the advertised max capacity.
func NewDynamicTable(maxCapacity uint64) *DynamicTable {
	dt := &DynamicTable{maxCapacity: maxCapacity}
	dt.cond = sync.NewCond(&dt.mu)
	return dt
}

// maxEntries is floor(maxCapacity/32), used for Required Insert Count
// reconstruction (RFC 9204 §4.5.1.1).
func (dt *DynamicTable) maxEntries() uint64 { return dt.maxCapacity / entryOverhead }

func (dt *DynamicTable) setCapacity(c uint64) error {
	if c > dt.maxCapacity {
		return fmt.Errorf("qpack: encoder set capacity %d > advertised max %d", c, dt.maxCapacity)
	}
	dt.capacity = c
	dt.evictToFit(0)
	return nil
}

// evictToFit evicts the oldest entries until size+extra <= capacity.
func (dt *DynamicTable) evictToFit(extra uint64) {
	for len(dt.entries) > 0 && dt.size+extra > dt.capacity {
		ev := dt.entries[0]
		dt.entries = dt.entries[1:]
		dt.size -= uint64(len(ev.Name)+len(ev.Value)) + entryOverhead
		dt.dropped++
	}
}

func (dt *DynamicTable) insert(hf HeaderField) error {
	sz := uint64(len(hf.Name)+len(hf.Value)) + entryOverhead
	if sz > dt.capacity {
		// Entry can never fit — evict everything and drop it (this is legal; the
		// encoder must not reference it).
		dt.evictToFit(dt.capacity + 1)
		return errors.New("qpack: dynamic table entry larger than capacity")
	}
	dt.evictToFit(sz)
	dt.entries = append(dt.entries, hf)
	dt.size += sz
	dt.insertCount++
	dt.cond.Broadcast()
	return nil
}

// InsertCount returns the total number of entries ever inserted, which is what
// the decoder acknowledges back to the peer (RFC 9204 4.4.3).
func (dt *DynamicTable) InsertCount() uint64 {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	return dt.insertCount
}

// atAbsolute returns the entry with the given absolute index.
func (dt *DynamicTable) atAbsolute(abs uint64) (HeaderField, bool) {
	if abs < dt.dropped || abs >= dt.insertCount {
		return HeaderField{}, false
	}
	return dt.entries[abs-dt.dropped], true
}

// waitForInserts blocks until insertCount >= n (the Required Insert Count), the
// encoder stream ends, or waitTimeout elapses. It must never block forever: the
// peer's encoder stream can die (or simply never deliver the inserts), and an
// unbounded wait here would hang the response decode — and therefore the request
// — with no way to cancel it.
func (dt *DynamicTable) waitForInserts(n uint64) {
	timer := time.AfterFunc(waitTimeout, func() {
		dt.mu.Lock()
		dt.timedOut = true
		dt.mu.Unlock()
		dt.cond.Broadcast()
	})
	defer timer.Stop()

	dt.mu.Lock()
	for dt.insertCount < n && !dt.closed && !dt.timedOut {
		dt.cond.Wait()
	}
	dt.mu.Unlock()
}

// close marks the encoder stream as finished and wakes every waiter, so blocked
// decodes fail with a normal decoding error instead of deadlocking.
func (dt *DynamicTable) close() {
	dt.mu.Lock()
	dt.closed = true
	dt.mu.Unlock()
	dt.cond.Broadcast()
}

// ParseEncoderInstructions reads the peer's QPACK encoder stream and applies its
// instructions to the dynamic table until the stream ends or errors. It is meant
// to run on its own goroutine for the connection lifetime.
func (dt *DynamicTable) ParseEncoderInstructions(r io.Reader) error {
	// However this returns (EOF, stream reset, protocol error), wake any decode
	// blocked in waitForInserts — otherwise it would wait forever.
	defer dt.close()
	br := newByteReader(r)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		switch {
		case b&0x80 != 0: // 1xxxxxxx: Insert With Name Reference
			isStatic := b&0x40 != 0
			nameIdx, err := br.readPrefixedInt(b, 6)
			if err != nil {
				return err
			}
			name, err := dt.nameForInsert(nameIdx, isStatic)
			if err != nil {
				return err
			}
			val, err := br.readString(7)
			if err != nil {
				return err
			}
			dt.mu.Lock()
			err = dt.insert(HeaderField{Name: name, Value: val})
			dt.mu.Unlock()
			if err != nil {
				return err
			}
		case b&0x40 != 0: // 01xxxxxx: Insert With Literal Name
			name, err := br.readStringWithFirst(b, 5)
			if err != nil {
				return err
			}
			val, err := br.readString(7)
			if err != nil {
				return err
			}
			dt.mu.Lock()
			err = dt.insert(HeaderField{Name: name, Value: val})
			dt.mu.Unlock()
			if err != nil {
				return err
			}
		case b&0x20 != 0: // 001xxxxx: Set Dynamic Table Capacity
			c, err := br.readPrefixedInt(b, 5)
			if err != nil {
				return err
			}
			dt.mu.Lock()
			err = dt.setCapacity(c)
			dt.mu.Unlock()
			if err != nil {
				return err
			}
		default: // 000xxxxx: Duplicate
			relIdx, err := br.readPrefixedInt(b, 5)
			if err != nil {
				return err
			}
			dt.mu.Lock()
			abs := dt.insertCount - 1 - relIdx
			hf, ok := dt.atAbsolute(abs)
			if ok {
				err = dt.insert(hf)
			} else {
				err = fmt.Errorf("qpack: duplicate of unknown entry %d", abs)
			}
			dt.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
}

func (dt *DynamicTable) nameForInsert(idx uint64, isStatic bool) (string, error) {
	if isStatic {
		if idx >= uint64(len(staticTableEntries)) {
			return "", invalidIndexError(idx)
		}
		return staticTableEntries[idx].Name, nil
	}
	// Dynamic name reference on the encoder stream is relative to the insertion
	// point: absolute = insertCount - 1 - idx.
	dt.mu.Lock()
	defer dt.mu.Unlock()
	abs := dt.insertCount - 1 - idx
	hf, ok := dt.atAbsolute(abs)
	if !ok {
		return "", invalidIndexError(idx)
	}
	return hf.Name, nil
}

// byteReader is a small buffered reader over the encoder stream that can decode
// QPACK prefixed integers and (Huffman) strings across the stream boundary.
type byteReader struct {
	r   io.Reader
	buf []byte
	pos int
}

func newByteReader(r io.Reader) *byteReader { return &byteReader{r: r} }

func (b *byteReader) fill() error {
	if b.pos < len(b.buf) {
		return nil
	}
	tmp := make([]byte, 4096)
	n, err := b.r.Read(tmp)
	if n > 0 {
		b.buf = tmp[:n]
		b.pos = 0
		return nil
	}
	if err == nil {
		err = io.EOF
	}
	return err
}

func (b *byteReader) ReadByte() (byte, error) {
	if err := b.fill(); err != nil {
		return 0, err
	}
	c := b.buf[b.pos]
	b.pos++
	return c, nil
}

// readPrefixedInt decodes a prefixed integer whose first byte is `first` and
// prefix length is n bits.
func (b *byteReader) readPrefixedInt(first byte, n byte) (uint64, error) {
	k := uint64(1<<n) - 1
	i := uint64(first) & k
	if i < k {
		return i, nil
	}
	var m uint64
	for {
		c, err := b.ReadByte()
		if err != nil {
			return 0, err
		}
		i += uint64(c&0x7f) << m
		if c&0x80 == 0 {
			return i, nil
		}
		m += 7
		if m >= 63 {
			return 0, errVarintOverflow
		}
	}
}

// readString reads a length-prefixed (Huffman-flagged) string; the first byte is
// read here and the Huffman bit is bit n.
func (b *byteReader) readString(n byte) (string, error) {
	first, err := b.ReadByte()
	if err != nil {
		return "", err
	}
	return b.readStringWithFirst(first, n)
}

func (b *byteReader) readStringWithFirst(first byte, n byte) (string, error) {
	huff := first&(1<<n) != 0
	l, err := b.readPrefixedInt(first, n)
	if err != nil {
		return "", err
	}
	data := make([]byte, l)
	for i := uint64(0); i < l; i++ {
		c, err := b.ReadByte()
		if err != nil {
			return "", err
		}
		data[i] = c
	}
	if huff {
		return hpack.HuffmanDecodeToString(data)
	}
	return string(data), nil
}
