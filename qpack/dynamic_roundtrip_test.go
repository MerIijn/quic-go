package qpack

import (
	"bytes"
	"io"
	"testing"
)

// Encode a header block with the dynamic-table encoder, feed the encoder-stream
// instructions into a decoder-side dynamic table, then decode the block and check
// we get the original fields back. This is the self-check for the request-side
// QPACK dynamic encoding: if this round-trips, the instruction, prefix and field
// line encodings are self-consistent.
func TestDynamicEncodeDecodeRoundTrip(t *testing.T) {
	fields := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "www.bol.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/nl/nl/"},
		{Name: "sec-ch-ua", Value: `"Not=A?Brand";v="99", "Google Chrome";v="151"`},
		{Name: "user-agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0"},
		{Name: "accept-encoding", Value: "gzip, deflate, br, zstd"},
		{Name: "accept-language", Value: "en-US,en;q=0.9"},
	}

	var block, encStream bytes.Buffer
	enc := NewEncoder(&block)
	enc.EnableDynamicTable(&encStream, 65536)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("WriteField: %v", err)
		}
	}
	if err := enc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if encStream.Len() == 0 {
		t.Fatal("no encoder-stream instructions emitted: the dynamic table was never used")
	}
	t.Logf("encoder stream: %d bytes, header block: %d bytes", encStream.Len(), block.Len())

	// Decoder side: apply the encoder instructions, then decode the block.
	dt := NewDynamicTable(65536)
	if err := dt.ParseEncoderInstructions(bytes.NewReader(encStream.Bytes())); err != nil && err != io.EOF {
		t.Fatalf("ParseEncoderInstructions: %v", err)
	}
	t.Logf("dynamic table: insertCount=%d", dt.insertCount)
	if dt.insertCount == 0 {
		t.Fatal("decoder inserted nothing")
	}

	dec := NewDecoder()
	dec.SetDynamicTable(dt)
	next := dec.Decode(block.Bytes())
	var got []HeaderField
	for {
		hf, err := next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		got = append(got, hf)
	}

	if len(got) != len(fields) {
		t.Fatalf("got %d fields, want %d: %+v", len(got), len(fields), got)
	}
	for i := range fields {
		if got[i] != fields[i] {
			t.Errorf("field %d: got %+v, want %+v", i, got[i], fields[i])
		}
	}
}
