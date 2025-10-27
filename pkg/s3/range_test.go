package s3

import (
	"testing"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		name        string
		rangeHeader string
		size        int64
		wantStart   int64
		wantEnd     int64
		wantErr     bool
	}{
		{
			name:        "valid range start-end",
			rangeHeader: "bytes=3701-3708",
			size:        10000,
			wantStart:   3701,
			wantEnd:     3708,
			wantErr:     false,
		},
		{
			name:        "valid range start only",
			rangeHeader: "bytes=100-",
			size:        1000,
			wantStart:   100,
			wantEnd:     999,
			wantErr:     false,
		},
		{
			name:        "range exceeds file size",
			rangeHeader: "bytes=0-10000",
			size:        5000,
			wantStart:   0,
			wantEnd:     4999,
			wantErr:     false,
		},
		{
			name:        "invalid range header",
			rangeHeader: "invalid",
			size:        1000,
			wantErr:     true,
		},
		{
			name:        "start greater than end",
			rangeHeader: "bytes=100-50",
			size:        1000,
			wantErr:     true,
		},
		{
			name:        "start equals file size",
			rangeHeader: "bytes=1000-1001",
			size:        1000,
			wantErr:     true,
		},
		{
			name:        "suffix range last 100 bytes",
			rangeHeader: "bytes=-100",
			size:        1000,
			wantStart:   900,
			wantEnd:     999,
			wantErr:     false,
		},
		{
			name:        "suffix range larger than file",
			rangeHeader: "bytes=-2000",
			size:        1000,
			wantStart:   0,
			wantEnd:     999,
			wantErr:     false,
		},
		{
			name:        "suffix range last 7153 bytes (Trino case)",
			rangeHeader: "bytes=-7153",
			size:        10000,
			wantStart:   2847,
			wantEnd:     9999,
			wantErr:     false,
		},
		{
			name:        "zero-length object suffix range",
			rangeHeader: "bytes=-100",
			size:        0,
			wantStart:   0,
			wantEnd:     -1,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := parseRange(tt.rangeHeader, tt.size)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseRange() error = nil, wantErr %v", tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("parseRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if start != tt.wantStart {
				t.Errorf("parseRange() start = %v, want %v", start, tt.wantStart)
			}

			if end != tt.wantEnd {
				t.Errorf("parseRange() end = %v, want %v", end, tt.wantEnd)
			}
		})
	}
}
