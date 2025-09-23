package storage

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
)

// StreamReader provides optimized streaming with parallel chunk reading
type StreamReader struct {
	ctx          context.Context
	reader       io.ReadCloser
	buffer       chan []byte
	bufferPool   *sync.Pool
	chunkSize    int
	prefetchSize int
	err          atomic.Value
	done         chan struct{}
	wg           sync.WaitGroup
}

// NewStreamReader creates an optimized stream reader with prefetching
func NewStreamReader(ctx context.Context, reader io.ReadCloser, chunkSize, prefetchSize int, pool *sync.Pool) *StreamReader {
	sr := &StreamReader{
		ctx:          ctx,
		reader:       reader,
		buffer:       make(chan []byte, prefetchSize),
		bufferPool:   pool,
		chunkSize:    chunkSize,
		prefetchSize: prefetchSize,
		done:         make(chan struct{}),
	}

	// Start prefetching
	sr.wg.Add(1)
	go sr.prefetch()

	return sr
}

func (sr *StreamReader) prefetch() {
	defer sr.wg.Done()
	defer close(sr.buffer)
	defer func() { _ = sr.reader.Close() }()

	for {
		select {
		case <-sr.ctx.Done():
			sr.err.Store(sr.ctx.Err())
			return
		case <-sr.done:
			return
		default:
			// Get buffer from pool
			buf := sr.bufferPool.Get().([]byte)
			if len(buf) < sr.chunkSize {
				buf = make([]byte, sr.chunkSize)
			}

			// Read chunk
			n, err := io.ReadFull(sr.reader, buf[:sr.chunkSize])
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				if n > 0 {
					select {
					case sr.buffer <- buf[:n]:
					case <-sr.ctx.Done():
						sr.bufferPool.Put(&buf)
						sr.err.Store(sr.ctx.Err())
						return
					case <-sr.done:
						sr.bufferPool.Put(&buf)
						return
					}
				} else {
					sr.bufferPool.Put(&buf)
				}
				return
			} else if err != nil {
				sr.bufferPool.Put(&buf)
				sr.err.Store(err)
				return
			}

			// Send to buffer channel
			select {
			case sr.buffer <- buf[:n]:
			case <-sr.ctx.Done():
				sr.bufferPool.Put(&buf)
				sr.err.Store(sr.ctx.Err())
				return
			case <-sr.done:
				sr.bufferPool.Put(&buf)
				return
			}
		}
	}
}

func (sr *StreamReader) Read(p []byte) (n int, err error) {
	// Check for stored error
	if v := sr.err.Load(); v != nil {
		return 0, v.(error)
	}

	totalRead := 0

	for totalRead < len(p) {
		select {
		case chunk, ok := <-sr.buffer:
			if !ok {
				// Channel closed, check for error
				if v := sr.err.Load(); v != nil {
					return totalRead, v.(error)
				}
				if totalRead > 0 {
					return totalRead, nil
				}
				return 0, io.EOF
			}

			// Copy data
			copied := copy(p[totalRead:], chunk)
			totalRead += copied

			// Return unused portion to pool
			if copied < len(chunk) {
				// Partial read, save remainder
				remainder := make([]byte, len(chunk)-copied)
				copy(remainder, chunk[copied:])

				// Try to put back for next read
				select {
				case sr.buffer <- remainder:
				default:
					// Buffer full, just continue
				}
			}

			// Return buffer to pool
			sr.bufferPool.Put(&chunk)

		case <-sr.ctx.Done():
			return totalRead, sr.ctx.Err()
		}
	}

	return totalRead, nil
}

func (sr *StreamReader) Close() error {
	close(sr.done)
	sr.wg.Wait()
	return nil
}

// ParallelWriter provides optimized parallel writing
type ParallelWriter struct {
	ctx         context.Context
	writeFunc   func(ctx context.Context, data []byte, offset int64) error
	bufferPool  *sync.Pool
	chunkSize   int
	parallelism int
	offset      int64
	mu          sync.Mutex
	wg          sync.WaitGroup
	errChan     chan error
	writeChan   chan *writeRequest
}

type writeRequest struct {
	data   []byte
	offset int64
}

// NewParallelWriter creates a parallel writer for fast uploads
func NewParallelWriter(ctx context.Context, writeFunc func(context.Context, []byte, int64) error, chunkSize, parallelism int, pool *sync.Pool) *ParallelWriter {
	pw := &ParallelWriter{
		ctx:         ctx,
		writeFunc:   writeFunc,
		bufferPool:  pool,
		chunkSize:   chunkSize,
		parallelism: parallelism,
		errChan:     make(chan error, parallelism),
		writeChan:   make(chan *writeRequest, parallelism*2),
	}

	// Start workers
	for i := 0; i < parallelism; i++ {
		pw.wg.Add(1)
		go pw.worker()
	}

	return pw
}

func (pw *ParallelWriter) worker() {
	defer pw.wg.Done()

	for req := range pw.writeChan {
		err := pw.writeFunc(pw.ctx, req.data, req.offset)
		if err != nil {
			select {
			case pw.errChan <- err:
			default:
			}
		}
		// Return buffer to pool
		pw.bufferPool.Put(&req.data)
	}
}

func (pw *ParallelWriter) Write(p []byte) (n int, err error) {
	// Check for errors
	select {
	case err := <-pw.errChan:
		return 0, err
	default:
	}

	// Get current offset
	pw.mu.Lock()
	offset := pw.offset
	pw.offset += int64(len(p))
	pw.mu.Unlock()

	// Copy data to avoid race conditions
	data := pw.bufferPool.Get().([]byte)
	if cap(data) < len(p) {
		data = make([]byte, len(p))
	} else {
		data = data[:len(p)]
	}
	copy(data, p)

	// Send write request
	select {
	case pw.writeChan <- &writeRequest{data: data, offset: offset}:
		return len(p), nil
	case <-pw.ctx.Done():
		pw.bufferPool.Put(&data)
		return 0, pw.ctx.Err()
	case err := <-pw.errChan:
		pw.bufferPool.Put(&data)
		return 0, err
	}
}

func (pw *ParallelWriter) Close() error {
	close(pw.writeChan)
	pw.wg.Wait()

	// Check for any errors
	select {
	case err := <-pw.errChan:
		return err
	default:
		return nil
	}
}
