package utils

import (
	"bytes"
	"io"
	"testing"
)

// growable is a simple in-memory WriterAt for testing SectionWriter.
type growable struct {
	buf []byte
}

func (g *growable) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(g.buf) {
		g.buf = append(g.buf, make([]byte, end-len(g.buf))...)
	}
	copy(g.buf[off:], p)
	return len(p), nil
}

// TestSectionWriter_Write checks sequential writes within bounds.
func TestSectionWriter_Write(t *testing.T) {
	g := &growable{}
	sw := NewSectionWriter(g, 10, 8) // offset=10, size=8

	n, err := sw.Write([]byte("hello")) // 5 bytes
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Fatalf("Write n=%d, want 5", n)
	}

	n, err = sw.Write([]byte("xyz")) // 3 more = 8 total, exactly at limit
	if err != nil {
		t.Fatalf("Write2: %v", err)
	}
	if n != 3 {
		t.Fatalf("Write2 n=%d, want 3", n)
	}

	got := g.buf[10:18]
	want := []byte("helloxyz")
	if !bytes.Equal(got, want) {
		t.Fatalf("SectionWriter data: got %q, want %q", got, want)
	}
}

// TestSectionWriter_WriteOverflow verifies that writing past the size limit returns ErrShortWrite.
func TestSectionWriter_WriteOverflow(t *testing.T) {
	g := &growable{}
	sw := NewSectionWriter(g, 0, 4) // size=4

	_, err := sw.Write([]byte("toolong")) // 7 bytes > 4
	if err != io.ErrShortWrite {
		t.Fatalf("Expected ErrShortWrite, got %v", err)
	}
}

// TestSectionWriter_WriteAt checks absolute writes within the section.
func TestSectionWriter_WriteAt(t *testing.T) {
	g := &growable{}
	sw := NewSectionWriter(g, 5, 10) // offset=5, size=10

	n, err := sw.WriteAt([]byte("abc"), 2)
	if err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if n != 3 {
		t.Fatalf("WriteAt n=%d, want 3", n)
	}

	got := g.buf[7:10] // base(5) + offset(2) = 7
	if string(got) != "abc" {
		t.Fatalf("WriteAt data: got %q, want %q", string(got), "abc")
	}
}

// TestSectionWriter_WriteAtOverflow verifies WriteAt rejects out-of-bounds writes.
func TestSectionWriter_WriteAtOverflow(t *testing.T) {
	g := &growable{}
	sw := NewSectionWriter(g, 0, 4) // size=4

	_, err := sw.WriteAt([]byte("toolong"), 0) // 7 bytes at offset 0, total 7 > 4
	if err != io.ErrShortWrite {
		t.Fatalf("Expected ErrShortWrite on WriteAt overflow, got %v", err)
	}
}

// TestSectionWriter_UnboundedSize verifies that size=-1 allows unlimited writes.
func TestSectionWriter_UnboundedSize(t *testing.T) {
	g := &growable{}
	sw := NewSectionWriter(g, 0, -1) // no size limit

	payload := make([]byte, 1000)
	for i := range payload {
		payload[i] = byte(i)
	}
	n, err := sw.Write(payload)
	if err != nil {
		t.Fatalf("Unbounded Write: %v", err)
	}
	if n != 1000 {
		t.Fatalf("Unbounded Write n=%d, want 1000", n)
	}
}

// TestBufReaderAt_ReadSequential verifies sequential reads from a buffered reader.
func TestBufReaderAt_ReadSequential(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstuvwxyz")
	bra := NewBufReaderAt(bytes.NewReader(data), 8) // buffer=8

	// Read first 8 bytes
	buf := make([]byte, 8)
	n, err := bra.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt(0,8): %v", err)
	}
	if n != 8 || string(buf) != "abcdefgh" {
		t.Fatalf("ReadAt(0,8): n=%d, data=%q", n, buf)
	}

	// Read bytes 4-8 (overlap with cache)
	buf2 := make([]byte, 4)
	n2, err2 := bra.ReadAt(buf2, 4)
	if err2 != nil && err2 != io.EOF {
		t.Fatalf("ReadAt(4,4): %v", err2)
	}
	if n2 != 4 || string(buf2) != "efgh" {
		t.Fatalf("ReadAt(4,4): n=%d, data=%q", n2, buf2)
	}
}

// TestBufReaderAt_ReadLargerThanBuffer verifies reads spanning multiple cache lines.
func TestBufReaderAt_ReadLargerThanBuffer(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	bra := NewBufReaderAt(bytes.NewReader(data), 8) // buffer=8

	buf := make([]byte, 20) // larger than buffer
	n, err := bra.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt large: %v", err)
	}
	if n != 20 {
		t.Fatalf("ReadAt large n=%d, want 20", n)
	}
	for i := 0; i < 20; i++ {
		if buf[i] != byte(i) {
			t.Fatalf("ReadAt large data[%d]=%d, want %d", i, buf[i], i)
		}
	}
}

// TestBufReaderAt_NonSequentialRead verifies random access.
func TestBufReaderAt_NonSequentialRead(t *testing.T) {
	data := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	bra := NewBufReaderAt(bytes.NewReader(data), 4)

	// Read from the middle
	buf := make([]byte, 3)
	n, err := bra.ReadAt(buf, 10)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt(10,3): %v", err)
	}
	if n != 3 || string(buf) != "KLM" {
		t.Fatalf("ReadAt(10,3): n=%d, data=%q", n, buf)
	}
}

// TestBufReaderAt_SmallBufferFloor verifies that buffer sizes below minBufferSize are promoted.
func TestBufReaderAt_SmallBufferFloor(t *testing.T) {
	data := []byte("hello")
	bra := NewBufReaderAt(bytes.NewReader(data), 1) // below minBufferSize=4

	buf := make([]byte, 5)
	n, err := bra.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt small: %v", err)
	}
	if n != 5 || string(buf) != "hello" {
		t.Fatalf("ReadAt small: n=%d, data=%q", n, buf)
	}
}
