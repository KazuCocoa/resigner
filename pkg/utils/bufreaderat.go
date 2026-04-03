package utils

import "io"

const minBufSize = 4096

// BufReaderAt wraps an io.ReaderAt with a fixed-size aligned block cache.
// Reads smaller than the cache that fall within the same aligned block are
// served without calling the underlying reader.
type BufReaderAt struct {
	r     io.ReaderAt
	buf   []byte
	base  int64 // file offset of buf[0]
	valid int   // number of valid bytes in buf
	ready bool  // true once buf contains data
}

// NewBufReaderAt returns a BufReaderAt wrapping r with a cache of the given
// size. The minimum cache size is 4096 bytes.
func NewBufReaderAt(r io.ReaderAt, size int) *BufReaderAt {
	if size < minBufSize {
		size = minBufSize
	}
	return &BufReaderAt{r: r, buf: make([]byte, size)}
}

// ReadAt implements io.ReaderAt. Reads larger than the cache are forwarded
// directly to the underlying reader. Smaller reads that hit the cached block
// avoid a round-trip to the underlying reader.
func (b *BufReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Large reads bypass the cache.
	if len(p) > len(b.buf) {
		return b.r.ReadAt(p, off)
	}

	blockSize := int64(len(b.buf))
	blockStart := (off / blockSize) * blockSize
	end := off + int64(len(p))

	// Cache hit: requested range lies entirely within the cached block.
	if b.ready && blockStart == b.base && end <= b.base+int64(b.valid) {
		copy(p, b.buf[off-b.base:])
		return len(p), nil
	}

	// Cache miss: load the aligned block that contains off.
	n, _ := b.r.ReadAt(b.buf, blockStart)
	b.base = blockStart
	b.valid = n
	b.ready = true

	if end <= blockStart+int64(n) {
		copy(p, b.buf[off-blockStart:])
		return len(p), nil
	}

	// The read crosses a block boundary or extends past EOF; fall back to a
	// direct read.
	return b.r.ReadAt(p, off)
}
