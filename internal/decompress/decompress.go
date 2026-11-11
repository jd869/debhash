// Package decompress opens the compressed streams found in Debian archives
// (.gz, .xz, .zst, .bz2) based on the file name suffix.
package decompress

import (
	"compress/bzip2"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Open wraps r with a decompressor chosen by name's suffix. Names without a
// known compression suffix are returned unchanged. The caller must Close the
// result; closing does not close r.
func Open(name string, r io.Reader) (io.ReadCloser, error) {
	switch {
	case strings.HasSuffix(name, ".gz"):
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gzip %s: %w", name, err)
		}
		return zr, nil
	case strings.HasSuffix(name, ".xz"):
		zr, err := xz.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("xz %s: %w", name, err)
		}
		return io.NopCloser(zr), nil
	case strings.HasSuffix(name, ".zst"):
		// Low-memory, single-goroutine decoding: we stream many debs in
		// parallel and want each one to stay small.
		zr, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))
		if err != nil {
			return nil, fmt.Errorf("zstd %s: %w", name, err)
		}
		return zstdCloser{zr}, nil
	case strings.HasSuffix(name, ".bz2"):
		return io.NopCloser(bzip2.NewReader(r)), nil
	default:
		return io.NopCloser(r), nil
	}
}

type zstdCloser struct{ *zstd.Decoder }

func (z zstdCloser) Close() error { z.Decoder.Close(); return nil }
