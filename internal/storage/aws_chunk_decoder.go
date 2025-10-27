package storage

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// AWSChunkDecoder decodes AWS V4 streaming chunks without validation.
// It strips chunk headers and signatures, returning only the actual data.
type AWSChunkDecoder struct {
	reader         *bufio.Reader
	done           bool
	bytesRead      int64
	chunkRemaining int64
}

// NewAWSChunkDecoder creates a new chunk decoder.
func NewAWSChunkDecoder(r io.Reader) *AWSChunkDecoder {
	return &AWSChunkDecoder{
		reader: bufio.NewReaderSize(r, 2*1024*1024), // 2MB buffer for large chunks
	}
}

func (d *AWSChunkDecoder) Read(p []byte) (int, error) {
	if d.done {
		return 0, io.EOF
	}

	totalRead := 0
	for totalRead < len(p) {
		if d.chunkRemaining == 0 {
			size, err := d.readChunkHeader()
			if err != nil {
				if err == io.EOF {
					d.done = true
				}
				// If this looks like a chunk parsing error on binary data, fail fast
				if strings.Contains(err.Error(), "client declared chunked encoding but sent raw data") {
					logrus.WithError(err).Error("Detected raw data being processed as chunks - aborting to prevent corruption")
					return 0, fmt.Errorf("chunk decoder received non-chunked data: %w", err)
				}
				logrus.WithFields(logrus.Fields{
					"error":     err,
					"bytesRead": d.bytesRead,
					"totalRead": totalRead,
				}).Debug("Chunk header read error")
				if totalRead > 0 {
					return totalRead, nil
				}
				return 0, err
			}

			if size == 0 {
				if err := d.consumeCRLF(); err != nil && !errors.Is(err, io.EOF) {
					logrus.WithError(err).Debug("Failed to consume final chunk CRLF")
				}
				if err := d.consumeTrailers(); err != nil && !errors.Is(err, io.EOF) {
					logrus.WithError(err).Debug("Failed to consume chunk trailers")
				}
				d.done = true
				logrus.WithFields(logrus.Fields{
					"totalBytesRead": d.bytesRead,
					"totalRead":      totalRead,
				}).Debug("Finished reading all chunks")
				if totalRead > 0 {
					return totalRead, nil
				}
				return 0, io.EOF
			}

			d.chunkRemaining = size
			logrus.WithFields(logrus.Fields{
				"chunkSize":     size,
				"chunkRemaining": d.chunkRemaining,
				"totalBytesRead": d.bytesRead,
			}).Debug("Started new chunk")
		}

		if len(p) == 0 {
			return totalRead, nil
		}

		remaining := len(p) - totalRead
		toRead := int64(remaining)
		if toRead > d.chunkRemaining {
			toRead = d.chunkRemaining
		}

		n, err := d.reader.Read(p[totalRead : totalRead+int(toRead)])
		if n > 0 {
			d.bytesRead += int64(n)
			d.chunkRemaining -= int64(n)
			totalRead += n
			logrus.WithFields(logrus.Fields{
				"chunkBytesRead": n,
				"chunkRemaining": d.chunkRemaining,
				"totalBytesRead": d.bytesRead,
				"totalRead":      totalRead,
			}).Debug("Read chunk data")
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				if d.chunkRemaining == 0 {
					if cerr := d.consumeCRLF(); cerr != nil && !errors.Is(cerr, io.EOF) {
						logrus.WithError(cerr).Debug("Failed to consume chunk CRLF after EOF")
					}
					continue
				} else {
					logrus.WithFields(logrus.Fields{
						"chunkRemaining": d.chunkRemaining,
						"totalRead":      totalRead,
					}).Error("Unexpected EOF in middle of chunk")
					if totalRead > 0 {
						return totalRead, nil
					}
					return 0, fmt.Errorf("unexpected EOF with %d bytes remaining in chunk", d.chunkRemaining)
				}
			}
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, err
		}

		if n == 0 {
			logrus.WithFields(logrus.Fields{
				"chunkRemaining": d.chunkRemaining,
				"totalRead":      totalRead,
			}).Debug("Zero bytes read, continuing")
			continue
		}

		if d.chunkRemaining == 0 {
			if err := d.consumeCRLF(); err != nil && !errors.Is(err, io.EOF) {
				logrus.WithError(err).Debug("Failed to consume chunk CRLF")
			}
		}
	}

	return totalRead, nil
}

func (d *AWSChunkDecoder) readChunkHeader() (int64, error) {
	header, err := d.readLine()
	if err != nil {
		return 0, err
	}

	if header == "" {
		return 0, io.EOF
	}

	// Validate chunk header format early
	if d.looksLikeRawData(header) {
		logrus.WithField("header", header).Error("Detected raw data instead of chunk header")
		return 0, fmt.Errorf("client declared chunked encoding but sent raw data: header='%s'", header)
	}

	size := int64(0)
	if idx := strings.Index(header, ";chunk-signature="); idx > 0 {
		sizeStr := header[:idx]
		parsedSize, parseErr := strconv.ParseInt(sizeStr, 16, 64)
		if parseErr != nil {
			logrus.WithFields(logrus.Fields{
				"header":  header,
				"sizeStr": sizeStr,
				"error":   parseErr,
			}).Error("Failed to parse chunk size with signature")
			return 0, fmt.Errorf("invalid chunk size '%s': %w", sizeStr, parseErr)
		}
		size = parsedSize
	} else {
		parsedSize, parseErr := strconv.ParseInt(header, 16, 64)
		if parseErr != nil {
			logrus.WithFields(logrus.Fields{
				"header": header,
				"error":  parseErr,
			}).Error("Failed to parse chunk header")
			return 0, fmt.Errorf("invalid chunk header '%s': %w", header, parseErr)
		}
		size = parsedSize
	}

	// Validate size is reasonable (prevent negative or extremely large chunks)
	if size < 0 || size > 100*1024*1024 { // 100MB max chunk size
		logrus.WithFields(logrus.Fields{
			"header": header,
			"size":   size,
		}).Error("Invalid chunk size detected")
		return 0, fmt.Errorf("invalid chunk size %d in header '%s'", size, header)
	}

	return size, nil
}

func (d *AWSChunkDecoder) consumeCRLF() error {
	buf := make([]byte, 2)
	_, err := io.ReadFull(d.reader, buf)
	if err != nil {
		return err
	}
	if !bytes.Equal(buf, []byte("\r\n")) {
		logrus.WithField("bytes", buf).Debug("Trailing bytes were not CRLF")
	}
	return nil
}

func (d *AWSChunkDecoder) consumeTrailers() error {
	for {
		line, err := d.readLineWithTimeout(5 * time.Second)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
}

func (d *AWSChunkDecoder) readLine() (string, error) {
	return d.readLineWithTimeout(30 * time.Second)
}

func (d *AWSChunkDecoder) readLineWithTimeout(timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	lineChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		line, err := d.reader.ReadString('\n')
		if err != nil {
			errChan <- err
			return
		}

		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		lineChan <- line
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("readline timeout after %s", timeout)
	case line := <-lineChan:
		return line, nil
	case err := <-errChan:
		return "", err
	}
}

// GetBytesRead returns the total bytes read (including chunk overhead).
func (d *AWSChunkDecoder) GetBytesRead() int64 {
	return d.bytesRead
}

// looksLikeRawData checks if the header looks like raw data instead of a chunk header.
func (d *AWSChunkDecoder) looksLikeRawData(header string) bool {
	if strings.Contains(header, "\"") || strings.Contains(header, "{") || strings.Contains(header, "}") {
		return true
	}

	if len(header) > 0 && (header[0] < 32 || header[0] > 126) {
		return true
	}

	if len(header) > 0 {
		sizePart := header
		if idx := strings.Index(header, ";"); idx > 0 {
			sizePart = header[:idx]
		}

		for _, ch := range sizePart {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return true
			}
		}
	}

	return false
}
