package stream

import (
	"io"
)

// ReadCloser wraps an io.Reader to implement io.ReadCloser
type ReadCloser struct {
	io.Reader
}

// Close implements io.ReadCloser
func (rc ReadCloser) Close() error {
	if closer, ok := rc.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// WrapReader wraps an io.Reader as io.ReadCloser
func WrapReader(r io.Reader) io.ReadCloser {
	if rc, ok := r.(io.ReadCloser); ok {
		return rc
	}
	return ReadCloser{Reader: r}
}
