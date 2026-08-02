package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	maxExpandedArchiveBytes int64 = 512 << 20
	maxZIPEntries                 = 4096
)

// extractArchive copies the exact regular root member named memberName from
// archive into destination, returning the number of bytes written. archive
// is dispatched on assetName's suffix; archiveSize is required for the ZIP
// central-directory reader and ignored for tar.gz.
func extractArchive(ctx context.Context, assetName string, archive *os.File, archiveSize int64, memberName string, destination io.Writer) (int64, error) {
	switch {
	case strings.HasSuffix(assetName, ".tar.gz"):
		return extractTarGzContext(ctx, archive, memberName, maxExpandedArchiveBytes, destination)
	case strings.HasSuffix(assetName, ".zip"):
		return extractZIPContext(ctx, archive, archiveSize, memberName, destination)
	default:
		return 0, fmt.Errorf("unsupported archive name %q", assetName)
	}
}

func extractTarGzContext(ctx context.Context, archive *os.File, memberName string, maxExpanded int64, destination io.Writer) (int64, error) {
	compressed := &contextReader{ctx: ctx, reader: archive}
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return 0, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	limited := &io.LimitedReader{R: gzipReader, N: maxExpanded + 1}
	tarReader := tar.NewReader(limited)
	var written int64
	found := false
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("read tar archive: %w", err)
		}
		if path.Base(header.Name) != memberName {
			continue
		}
		if header.Name != memberName {
			return 0, fmt.Errorf("binary member %q is not at the archive root", header.Name)
		}
		if header.Typeflag != tar.TypeReg {
			return 0, fmt.Errorf("binary member %q is not a regular file", header.Name)
		}
		if found {
			return 0, fmt.Errorf("archive contains duplicate binary member %q", memberName)
		}
		if header.Size <= 0 {
			return 0, fmt.Errorf("binary member %q is empty", memberName)
		}
		if header.Size > maxBinaryBytes {
			return 0, fmt.Errorf("binary member %q exceeds the %d-byte limit", memberName, maxBinaryBytes)
		}
		// tar.Reader clamps reads for the current entry to header.Size, so
		// CopyN either copies exactly header.Size bytes (err == nil, and by
		// io.CopyN's contract the returned count then equals header.Size) or
		// fails if the entry's actual data is shorter than declared.
		copied, err := io.CopyN(destination, tarReader, header.Size)
		if err != nil {
			return 0, fmt.Errorf("read binary member %q: %w", memberName, err)
		}
		if copied != header.Size {
			return 0, fmt.Errorf("binary member %q has an invalid expanded size", memberName)
		}
		written = copied
		found = true
	}
	if limited.N <= 0 {
		return 0, fmt.Errorf("expanded archive exceeds the %d-byte limit", maxExpanded)
	}
	if !found {
		return 0, fmt.Errorf("archive has no exact regular root member %q", memberName)
	}
	return written, nil
}

func extractZIPContext(ctx context.Context, archive *os.File, archiveSize int64, memberName string, destination io.Writer) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	reader, err := zip.NewReader(archive, archiveSize)
	if err != nil {
		return 0, fmt.Errorf("open ZIP archive: %w", err)
	}
	if len(reader.File) > maxZIPEntries {
		return 0, fmt.Errorf("ZIP archive has more than %d entries", maxZIPEntries)
	}
	var written int64
	found := false
	for _, file := range reader.File {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if path.Base(file.Name) != memberName {
			continue
		}
		if file.Name != memberName {
			return 0, fmt.Errorf("binary member %q is not at the archive root", file.Name)
		}
		if !file.Mode().IsRegular() {
			return 0, fmt.Errorf("binary member %q is not a regular file", file.Name)
		}
		if found {
			return 0, fmt.Errorf("archive contains duplicate binary member %q", memberName)
		}
		if file.UncompressedSize64 == 0 {
			return 0, fmt.Errorf("binary member %q is empty", memberName)
		}
		if file.UncompressedSize64 > uint64(maxBinaryBytes) {
			return 0, fmt.Errorf("binary member %q exceeds the %d-byte limit", memberName, maxBinaryBytes)
		}
		opened, err := file.Open()
		if err != nil {
			return 0, fmt.Errorf("open binary member %q: %w", memberName, err)
		}
		// The declared UncompressedSize64 is untrusted central-directory
		// metadata; the actual decompressed length can differ from it. Bound
		// the read at maxBinaryBytes+1 exactly as before (not at the
		// declared size) and compare the copied count to the declared size
		// afterward, so neither a short nor a long mismatch is silently
		// accepted.
		copied, err := io.Copy(destination, io.LimitReader(&contextReader{ctx: ctx, reader: opened}, maxBinaryBytes+1))
		closeErr := opened.Close()
		if err != nil {
			return 0, fmt.Errorf("read binary member %q: %w", memberName, err)
		}
		if closeErr != nil {
			return 0, fmt.Errorf("close binary member %q: %w", memberName, closeErr)
		}
		if uint64(copied) != file.UncompressedSize64 || copied > maxBinaryBytes {
			return 0, fmt.Errorf("binary member %q has an invalid expanded size", memberName)
		}
		written = copied
		found = true
	}
	if !found {
		return 0, fmt.Errorf("archive has no exact regular root member %q", memberName)
	}
	return written, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
