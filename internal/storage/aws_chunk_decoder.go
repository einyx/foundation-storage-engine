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

	for {
		if d.chunkRemaining == 0 {
			size, err := d.readChunkHeader()
			if err != nil {
				if err == io.EOF {
					d.done = true
				}
				logrus.WithFields(logrus.Fields{
					"error":     err,
					"bytesRead": d.bytesRead,
				}).Debug("Chunk header read error")
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
				logrus.WithField("totalBytesRead", d.bytesRead).Debug("Finished reading all chunks")
				return 0, io.EOF
			}

			d.chunkRemaining = size
		}

		if len(p) == 0 {
			return 0, nil
		}

		toRead := int64(len(p))
		if toRead > d.chunkRemaining {
			toRead = d.chunkRemaining
		}

		n, err := d.reader.Read(p[:toRead])
		if n > 0 {
			d.bytesRead += int64(n)
			d.chunkRemaining -= int64(n)
		}

		if err != nil {
			if errors.Is(err, io.EOF) && d.chunkRemaining == 0 {
				if cerr := d.consumeCRLF(); cerr != nil && !errors.Is(cerr, io.EOF) {
					logrus.WithError(cerr).Debug("Failed to consume chunk CRLF after EOF")
				}
				continue
			}
			return n, err
		}

		if n == 0 {
			continue
		}

		if d.chunkRemaining == 0 {
			if err := d.consumeCRLF(); err != nil && !errors.Is(err, io.EOF) {
				logrus.WithError(err).Debug("Failed to consume chunk CRLF")
			}
		}

		return n, nil
	}
}

func (d *AWSChunkDecoder) readChunkHeader() (int64, error) {
	header, err := d.readLine()
	if err != nil {
		return 0, err
	}

	if header == "" {
		return 0, io.EOF
	}

	size := int64(0)
	if idx := strings.Index(header, ";chunk-signature="); idx > 0 {
		sizeStr := header[:idx]
		parsedSize, parseErr := strconv.ParseInt(sizeStr, 16, 64)
		if parseErr != nil {
			if d.looksLikeRawData(header) {
				return 0, fmt.Errorf("client declared chunked encoding but sent raw data")
			}
			logrus.WithFields(logrus.Fields{
				"header":  header,
				"sizeStr": sizeStr,
				"error":   parseErr,
			}).Error("Failed to parse chunk size")
			return 0, fmt.Errorf("invalid chunk size '%s': %w", sizeStr, parseErr)
		}
		size = parsedSize
	} else {
		parsedSize, parseErr := strconv.ParseInt(header, 16, 64)
		if parseErr != nil {
			if d.looksLikeRawData(header) {
				return 0, fmt.Errorf("client declared chunked encoding but sent raw data")
			}
			return 0, fmt.Errorf("invalid chunk header '%s': %w", header, parseErr)
		}
		size = parsedSize
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
