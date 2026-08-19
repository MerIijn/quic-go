package qpack

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

// An invalidIndexError is returned when decoding encounters an invalid index
// (e.g., an index that is out of bounds for the static table).
type invalidIndexError int

func (e invalidIndexError) Error() string {
	return fmt.Sprintf("invalid indexed representation index %d", int(e))
}

var errNoDynamicTable = errors.New("no dynamic table")

// A Decoder decodes QPACK header blocks.
// A Decoder can be reused to decode multiple header blocks on different streams
// on the same connection (e.g., headers then trailers).
type Decoder struct {
	// dt, when non-nil, enables dynamic-table decoding (RFC 9204). When nil the
	// decoder is static-only and rejects any header block with a non-zero
	// Required Insert Count, preserving the original upstream behavior.
	dt *DynamicTable
}

// DecodeFunc is a function that decodes the next header field from a header block.
// It should be called repeatedly until it returns io.EOF.
// It returns io.EOF when all header fields have been decoded.
// Any error other than io.EOF indicates a decoding error.
type DecodeFunc func() (HeaderField, error)

// NewDecoder returns a new Decoder.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// SetDynamicTable enables dynamic-table decoding against dt. Header blocks with
// dynamic references then resolve against it (blocking until the required
// inserts have arrived on the encoder stream).
func (d *Decoder) SetDynamicTable(dt *DynamicTable) { d.dt = dt }

// Decode returns a function that decodes header fields from the given header block.
// It does not copy the slice; the caller must ensure it remains valid during decoding.
// PeekRequiredInsertCount returns an encoded field section's Required Insert
// Count without decoding it. A non-zero count means the section referenced the
// dynamic table, which is what obliges the decoder to acknowledge the section
// on its stream (RFC 9204 4.4.1).
func (d *Decoder) PeekRequiredInsertCount(p []byte) (uint64, error) {
	enc, _, err := readVarInt(8, p)
	if err != nil {
		return 0, err
	}
	return d.reconstructRIC(enc)
}

func (d *Decoder) Decode(p []byte) DecodeFunc {
	var started bool
	var base uint64

	return func() (HeaderField, error) {
		if !started {
			started = true
			// Encoded Required Insert Count (RFC 9204 §4.5.1).
			encRIC, rest, err := readVarInt(8, p)
			if err != nil {
				return HeaderField{}, err
			}
			p = rest
			ric, err := d.reconstructRIC(encRIC)
			if err != nil {
				return HeaderField{}, err
			}
			// Base = RIC ± DeltaBase (S bit) (RFC 9204 §4.5.1.2).
			if len(p) == 0 {
				return HeaderField{}, io.ErrUnexpectedEOF
			}
			sign := p[0]&0x80 != 0
			deltaBase, rest2, err := readVarInt(7, p)
			if err != nil {
				return HeaderField{}, err
			}
			p = rest2
			if sign {
				base = ric - deltaBase - 1
			} else {
				base = ric + deltaBase
			}
			if ric > 0 {
				if d.dt == nil {
					return HeaderField{}, errors.New("qpack: dynamic reference without dynamic table")
				}
				// Block until the encoder stream has delivered enough inserts.
				d.dt.waitForInserts(ric)
			}
		}

		if len(p) == 0 {
			return HeaderField{}, io.EOF
		}

		b := p[0]
		var hf HeaderField
		var rest []byte
		var err error
		switch {
		case (b & 0x80) > 0: // 1Txxxxxx: Indexed Field Line
			hf, rest, err = d.parseIndexed(p, base)
		case (b & 0xc0) == 0x40: // 01NTxxxx: Literal With Name Reference
			hf, rest, err = d.parseLiteralWithNameRef(p, base)
		case (b & 0xe0) == 0x20: // 001NHxxx: Literal With Literal Name
			hf, rest, err = d.parseLiteralHeaderFieldWithoutNameReference(p)
		case (b & 0xf0) == 0x10: // 0001xxxx: Indexed With Post-Base Index
			hf, rest, err = d.parseIndexedPostBase(p, base)
		case (b & 0xf0) == 0x00: // 0000Nxxx: Literal With Post-Base Name Reference
			hf, rest, err = d.parseLiteralPostBaseNameRef(p, base)
		default:
			err = fmt.Errorf("unexpected type byte: %#x", b)
		}
		p = rest
		if err != nil {
			return HeaderField{}, err
		}
		return hf, nil
	}
}

// reconstructRIC turns the Encoded Required Insert Count into the absolute
// Required Insert Count (RFC 9204 §4.5.1.1).
func (d *Decoder) reconstructRIC(enc uint64) (uint64, error) {
	if enc == 0 {
		return 0, nil
	}
	if d.dt == nil {
		return 0, errors.New("expected Required Insert Count to be zero")
	}
	maxEntries := d.dt.maxEntries()
	fullRange := 2 * maxEntries
	if fullRange == 0 { // capacity < 32 bytes: no dynamic entries can exist
		return 0, errors.New("qpack: dynamic reference with zero-capacity table")
	}
	if enc > fullRange {
		return 0, errors.New("qpack: encoded Required Insert Count too large")
	}
	d.dt.mu.Lock()
	total := d.dt.insertCount
	d.dt.mu.Unlock()
	maxValue := total + maxEntries
	maxWrapped := (maxValue / fullRange) * fullRange
	ric := maxWrapped + enc - 1
	if ric > maxValue {
		if ric <= fullRange {
			return 0, errors.New("qpack: invalid Required Insert Count")
		}
		ric -= fullRange
	}
	if ric == 0 {
		return 0, errors.New("qpack: invalid Required Insert Count (zero)")
	}
	return ric, nil
}

// dynamicAt resolves an absolute dynamic-table index.
func (d *Decoder) dynamicAt(abs uint64) (HeaderField, bool) {
	if d.dt == nil {
		return HeaderField{}, false
	}
	d.dt.mu.Lock()
	defer d.dt.mu.Unlock()
	return d.dt.atAbsolute(abs)
}

// parseIndexed handles an Indexed Field Line (1Txxxxxx): static or dynamic
// (relative to Base).
func (d *Decoder) parseIndexed(buf []byte, base uint64) (HeaderField, []byte, error) {
	isStatic := buf[0]&0x40 != 0
	index, rest, err := readVarInt(6, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	if isStatic {
		hf, ok := d.at(index)
		if !ok {
			return HeaderField{}, buf, invalidIndexError(index)
		}
		return hf, rest, nil
	}
	abs := base - 1 - index
	hf, ok := d.dynamicAt(abs)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	return hf, rest, nil
}

// parseIndexedPostBase handles Indexed Field Line With Post-Base Index
// (0001xxxx): dynamic, absolute = Base + index.
func (d *Decoder) parseIndexedPostBase(buf []byte, base uint64) (HeaderField, []byte, error) {
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, ok := d.dynamicAt(base + index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	return hf, rest, nil
}

// parseLiteralWithNameRef handles Literal Field Line With Name Reference
// (01NTxxxx): name from static or dynamic (relative to Base) table, literal value.
func (d *Decoder) parseLiteralWithNameRef(buf []byte, base uint64) (HeaderField, []byte, error) {
	isStatic := buf[0]&0x10 != 0
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	var name string
	if isStatic {
		hf, ok := d.at(index)
		if !ok {
			return HeaderField{}, buf, invalidIndexError(index)
		}
		name = hf.Name
	} else {
		hf, ok := d.dynamicAt(base - 1 - index)
		if !ok {
			return HeaderField{}, buf, invalidIndexError(index)
		}
		name = hf.Name
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, buf, io.ErrUnexpectedEOF
	}
	usesHuffman := buf[0]&0x80 > 0
	val, rest, err := d.readString(buf, 7, usesHuffman)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: val}, rest, nil
}

// parseLiteralPostBaseNameRef handles Literal Field Line With Post-Base Name
// Reference (0000Nxxx): dynamic name at Base + index, literal value.
func (d *Decoder) parseLiteralPostBaseNameRef(buf []byte, base uint64) (HeaderField, []byte, error) {
	index, rest, err := readVarInt(3, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, ok := d.dynamicAt(base + index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	name := hf.Name
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, buf, io.ErrUnexpectedEOF
	}
	usesHuffman := buf[0]&0x80 > 0
	val, rest, err := d.readString(buf, 7, usesHuffman)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: val}, rest, nil
}

func (d *Decoder) parseIndexedHeaderField(buf []byte) (_ HeaderField, rest []byte, _ error) {
	if buf[0]&0x40 == 0 {
		return HeaderField{}, buf, errNoDynamicTable
	}
	index, rest, err := readVarInt(6, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, ok := d.at(index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	return hf, rest, nil
}

func (d *Decoder) parseLiteralHeaderField(buf []byte) (_ HeaderField, rest []byte, _ error) {
	if buf[0]&0x10 == 0 {
		return HeaderField{}, buf, errNoDynamicTable
	}
	// We don't need to check the value of the N-bit here.
	// It's only relevant when re-encoding header fields,
	// and determines whether the header field can be added to the dynamic table.
	// Since we don't support the dynamic table, we can ignore it.
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, ok := d.at(index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, buf, io.ErrUnexpectedEOF
	}
	usesHuffman := buf[0]&0x80 > 0
	val, rest, err := d.readString(rest, 7, usesHuffman)
	if err != nil {
		return HeaderField{}, rest, err
	}
	hf.Value = val
	return hf, rest, nil
}

func (d *Decoder) parseLiteralHeaderFieldWithoutNameReference(buf []byte) (_ HeaderField, rest []byte, _ error) {
	usesHuffmanForName := buf[0]&0x8 > 0
	name, rest, err := d.readString(buf, 3, usesHuffmanForName)
	if err != nil {
		return HeaderField{}, rest, err
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, rest, io.ErrUnexpectedEOF
	}
	usesHuffmanForVal := buf[0]&0x80 > 0
	val, rest, err := d.readString(buf, 7, usesHuffmanForVal)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: val}, rest, nil
}

func (d *Decoder) readString(buf []byte, n uint8, usesHuffman bool) (string, []byte, error) {
	l, buf, err := readVarInt(n, buf)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(buf)) < l {
		return "", nil, io.ErrUnexpectedEOF
	}
	var val string
	if usesHuffman {
		val, err = hpack.HuffmanDecodeToString(buf[:l])
		if err != nil {
			return "", nil, err
		}
	} else {
		val = string(buf[:l])
	}
	buf = buf[l:]
	return val, buf, nil
}

func (d *Decoder) at(i uint64) (hf HeaderField, ok bool) {
	if i >= uint64(len(staticTableEntries)) {
		return
	}
	return staticTableEntries[i], true
}
