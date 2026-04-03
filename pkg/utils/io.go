package utils

import (
	"io"
)

type SectionWriter struct {
	w      io.WriterAt
	base   int64
	cursor int64
	size   int64
}

func NewSectionWriter(w io.WriterAt, offset, size int64) *SectionWriter {
	return &SectionWriter{
		w:      w,
		base:   offset,
		cursor: 0,
		size:   size,
	}
}

func (s *SectionWriter) Write(p []byte) (int, error) {
	if s.size >= 0 && int64(len(p))+s.cursor > s.size {
		return 0, io.ErrShortWrite
	}

	n, err := s.w.WriteAt(p, s.base+s.cursor)
	if err != nil {
		return 0, err
	}

	s.cursor += int64(n)
	return n, nil
}

func (s *SectionWriter) WriteAt(p []byte, offset int64) (int, error) {
	if s.size >= 0 && int64(len(p))+offset > s.size {
		return 0, io.ErrShortWrite
	}
	return s.w.WriteAt(p, s.base+offset)
}
