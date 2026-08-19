package qpack

import (
	"bytes"
	"testing"
)

// A peer that allows no blocked streams must never receive a header block that
// references an entry it has not acknowledged: it would have to block, and a
// peer that forbids blocking simply never answers.
func TestNoReferencesWhenBlockingDisallowed(t *testing.T) {
	var block, encStream bytes.Buffer
	e := NewEncoder(&block)
	e.EnableDynamicTable(&encStream, 4096)
	e.SetBlockedStreams(0)
	e.SetStreamID(0)

	hf := HeaderField{Name: "user-agent", Value: "test-agent"}
	if err := e.WriteField(hf); err != nil {
		t.Fatal(err)
	}
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
	if encStream.Len() == 0 {
		t.Error("nothing written to the encoder stream: the entry should still be inserted")
	}
	if b := block.Bytes(); len(b) < 2 || b[0] != 0 {
		t.Errorf("first block should carry Required Insert Count 0, got % x", b)
	}

	// Once the peer acknowledges the insert, referencing it is safe.
	e.NoteInsertCountIncrement(1)
	block.Reset()
	e.SetStreamID(4)
	if err := e.WriteField(hf); err != nil {
		t.Fatal(err)
	}
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
	if b := block.Bytes(); len(b) < 3 || b[0] == 0 {
		t.Errorf("after acknowledgement the block should reference the entry, got % x", b)
	}
}

// With a blocking budget the encoder may reference an entry in the same block
// that inserts it, which is what a browser does against a peer that allows it.
func TestReferencesImmediatelyWhenBlockingAllowed(t *testing.T) {
	var block, encStream bytes.Buffer
	e := NewEncoder(&block)
	e.EnableDynamicTable(&encStream, 4096)
	e.SetBlockedStreams(100)
	e.SetStreamID(0)

	if err := e.WriteField(HeaderField{Name: "user-agent", Value: "test-agent"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
	if encStream.Len() == 0 {
		t.Fatal("no insert written to the encoder stream")
	}
	if b := block.Bytes(); len(b) < 3 || b[0] == 0 {
		t.Errorf("block should reference the just-inserted entry, got % x", b)
	}
}

// A Section Acknowledgment advances the encoder's view of what the peer holds.
func TestSectionAckAdvancesKnownReceived(t *testing.T) {
	var block, encStream bytes.Buffer
	e := NewEncoder(&block)
	e.EnableDynamicTable(&encStream, 4096)
	e.SetBlockedStreams(100)
	e.SetStreamID(8)

	if err := e.WriteField(HeaderField{Name: "accept-language", Value: "en"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
	e.NoteSectionAck(8)

	// Now the same entry can be referenced even with no blocking budget.
	e.SetBlockedStreams(0)
	block.Reset()
	e.SetStreamID(12)
	if err := e.WriteField(HeaderField{Name: "accept-language", Value: "en"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
	if b := block.Bytes(); len(b) < 3 || b[0] == 0 {
		t.Errorf("an acknowledged entry should be referenceable, got % x", b)
	}
}
