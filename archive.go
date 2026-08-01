package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const maxExpandedArchiveBytes int64 = 512 << 20

func extractArchive(ctx context.Context, assetName string, body []byte, memberName string) ([]byte, error) {
	switch {
	case strings.HasSuffix(assetName, ".tar.gz"):
		return extractTarGzContext(ctx, body, memberName)
	case strings.HasSuffix(assetName, ".zip"):
		return extractZIPContext(ctx, body, memberName)
	default:
		return nil, fmt.Errorf("unsupported archive name %q", assetName)
	}
}

func extractTarGz(body []byte, memberName string) ([]byte, error) {
	return extractTarGzContext(context.Background(), body, memberName)
}

func extractTarGzContext(ctx context.Context, body []byte, memberName string) ([]byte, error) {
	compressed := &contextReader{ctx: ctx, reader: bytes.NewReader(body)}
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	limited := &io.LimitedReader{R: gzipReader, N: maxExpandedArchiveBytes + 1}
	tarReader := tar.NewReader(limited)
	var binary []byte
	found := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar archive: %w", err)
		}
		if path.Base(header.Name) != memberName {
			continue
		}
		if header.Name != memberName {
			return nil, fmt.Errorf("binary member %q is not at the archive root", header.Name)
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("binary member %q is not a regular file", header.Name)
		}
		if found {
			return nil, fmt.Errorf("archive contains duplicate binary member %q", memberName)
		}
		if header.Size <= 0 {
			return nil, fmt.Errorf("binary member %q is empty", memberName)
		}
		if header.Size > maxBinaryBytes {
			return nil, fmt.Errorf("binary member %q exceeds the %d-byte limit", memberName, maxBinaryBytes)
		}
		binary, err = io.ReadAll(io.LimitReader(tarReader, maxBinaryBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read binary member %q: %w", memberName, err)
		}
		if int64(len(binary)) != header.Size || int64(len(binary)) > maxBinaryBytes {
			return nil, fmt.Errorf("binary member %q has an invalid expanded size", memberName)
		}
		found = true
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("expanded archive exceeds the %d-byte limit", maxExpandedArchiveBytes)
	}
	if !found {
		return nil, fmt.Errorf("archive has no exact regular root member %q", memberName)
	}
	return binary, nil
}

func extractZIP(body []byte, memberName string) ([]byte, error) {
	return extractZIPContext(context.Background(), body, memberName)
}

func extractZIPContext(ctx context.Context, body []byte, memberName string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open ZIP archive: %w", err)
	}
	var binary []byte
	found := false
	for _, file := range reader.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if path.Base(file.Name) != memberName {
			continue
		}
		if file.Name != memberName {
			return nil, fmt.Errorf("binary member %q is not at the archive root", file.Name)
		}
		if !file.Mode().IsRegular() {
			return nil, fmt.Errorf("binary member %q is not a regular file", file.Name)
		}
		if found {
			return nil, fmt.Errorf("archive contains duplicate binary member %q", memberName)
		}
		if file.UncompressedSize64 == 0 {
			return nil, fmt.Errorf("binary member %q is empty", memberName)
		}
		if file.UncompressedSize64 > uint64(maxBinaryBytes) {
			return nil, fmt.Errorf("binary member %q exceeds the %d-byte limit", memberName, maxBinaryBytes)
		}
		opened, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open binary member %q: %w", memberName, err)
		}
		binary, err = io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: opened}, maxBinaryBytes+1))
		closeErr := opened.Close()
		if err != nil {
			return nil, fmt.Errorf("read binary member %q: %w", memberName, err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close binary member %q: %w", memberName, closeErr)
		}
		if uint64(len(binary)) != file.UncompressedSize64 || int64(len(binary)) > maxBinaryBytes {
			return nil, fmt.Errorf("binary member %q has an invalid expanded size", memberName)
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("archive has no exact regular root member %q", memberName)
	}
	return binary, nil
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
