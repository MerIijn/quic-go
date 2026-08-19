package qpack

import (
	"bytes"
	"testing"
)

// RFC 7541 5.1 worked examples, plus the two decoder-stream instructions
// (RFC 9204 4.4) built on top of them.
func TestAppendPrefixedInt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern byte
		n       byte
		v       uint64
		want    []byte
	}{
		{"10 in a 5-bit prefix", 0x00, 5, 10, []byte{0x0a}},
		{"1337 in a 5-bit prefix", 0x00, 5, 1337, []byte{31, 154, 10}},
		{"42 in an 8-bit prefix", 0x00, 8, 42, []byte{42}},
		{"section ack, stream 0", 0x80, 7, 0, []byte{0x80}},
		{"section ack, stream 100", 0x80, 7, 100, []byte{0x80 | 100}},
		{"section ack, stream 200", 0x80, 7, 200, []byte{0xff, 73}},
		{"insert count increment 1", 0x00, 6, 1, []byte{0x01}},
		{"insert count increment 100", 0x00, 6, 100, []byte{0x3f, 37}},
	} {
		if got := AppendPrefixedInt(nil, tc.pattern, tc.n, tc.v); !bytes.Equal(got, tc.want) {
			t.Errorf("%s: got % x, want % x", tc.name, got, tc.want)
		}
	}
	// It appends rather than overwrites.
	if got := AppendPrefixedInt([]byte{0xaa}, 0x80, 7, 1); !bytes.Equal(got, []byte{0xaa, 0x81}) {
		t.Errorf("append: got % x", got)
	}
}
