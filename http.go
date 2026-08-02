package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	maxMetadataBytes int64 = 2 << 20
	maxArchiveBytes  int64 = 256 << 20
	maxBinaryBytes   int64 = 256 << 20
	maxErrorBytes    int64 = 64 << 10
)

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	HTMLURL     string        `json:"html_url"`
	PublishedAt time.Time     `json:"published_at"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Size        int64  `json:"size"`
	Digest      string `json:"digest"`
}

type releaseAsset struct {
	name        string
	downloadURL string
	digest      [sha256.Size]byte
	size        int64
}

type httpStatusError struct {
	description string
	statusCode  int
	detail      string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("selfupdate: fetch %s: HTTP %d: %s", e.description, e.statusCode, e.detail)
}

func (u *Updater) fetchLatestRelease(ctx context.Context, expectedAsset string) (Release, releaseAsset, error) {
	return u.fetchRelease(ctx, "releases/latest", expectedAsset)
}

func (u *Updater) fetchReleaseByTag(ctx context.Context, version, expectedAsset string) (Release, releaseAsset, error) {
	release, asset, err := u.fetchRelease(ctx, "releases/tags/"+url.PathEscape(version), expectedAsset)
	if err != nil {
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && statusErr.statusCode == http.StatusNotFound {
			return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: release %s not found: %w", version, err)
		}
		return Release{}, releaseAsset{}, err
	}
	if release.Version != version {
		return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: release tag %q does not match requested version %q", release.Version, version)
	}
	return release, asset, nil
}

func (u *Updater) fetchRelease(ctx context.Context, pathSuffix, expectedAsset string) (Release, releaseAsset, error) {
	base, err := url.Parse(u.apiBaseURL)
	if err != nil || !base.IsAbs() || base.Host == "" || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return Release{}, releaseAsset{}, errors.New("selfupdate: invalid GitHub API base URL")
	}
	if err := u.validateURL(base.String(), true); err != nil {
		return Release{}, releaseAsset{}, err
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/repos/" + url.PathEscape(u.owner) + "/" + url.PathEscape(u.repository) + "/" + pathSuffix

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: create release request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	request.Header.Set("User-Agent", "go-selfupdate")
	if u.githubToken != "" {
		request.Header.Set("Authorization", "Bearer "+u.githubToken)
	}
	client := *u.httpClient
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("selfupdate: GitHub API redirect rejected")
	}
	body, err := u.doWithClient(&client, request, maxMetadataBytes, "release metadata", nil)
	if err != nil {
		return Release{}, releaseAsset{}, err
	}

	var metadata githubRelease
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&metadata); err != nil {
		return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: decode release metadata: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return Release{}, releaseAsset{}, err
	}
	if metadata.Draft {
		return Release{}, releaseAsset{}, errors.New("selfupdate: release metadata is flagged as draft")
	}
	if metadata.Prerelease {
		return Release{}, releaseAsset{}, errors.New("selfupdate: release metadata is flagged as prerelease")
	}
	if !isStableVersion(metadata.TagName) {
		return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: latest release tag %q is not exact vMAJOR.MINOR.PATCH", metadata.TagName)
	}
	if metadata.PublishedAt.IsZero() {
		return Release{}, releaseAsset{}, errors.New("selfupdate: release metadata has no publication time")
	}
	if err := u.validateURL(metadata.HTMLURL, false); err != nil {
		return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: invalid release page URL: %w", err)
	}

	var selected releaseAsset
	for _, asset := range metadata.Assets {
		if asset.Name != expectedAsset {
			continue
		}
		if selected.name != "" {
			return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: release has duplicate asset %q", asset.Name)
		}
		if asset.Size <= 0 {
			return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: asset %q has invalid size %d", asset.Name, asset.Size)
		}
		if asset.Size > maxArchiveBytes {
			return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: asset %q exceeds the %d-byte limit", asset.Name, maxArchiveBytes)
		}
		if err := u.validateURL(asset.DownloadURL, false); err != nil {
			return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: invalid URL for asset %q: %w", asset.Name, err)
		}
		digest, err := parseAssetDigest(asset.Digest)
		if err != nil {
			return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: invalid digest for asset %q: %w", asset.Name, err)
		}
		selected = releaseAsset{name: asset.Name, downloadURL: asset.DownloadURL, digest: digest, size: asset.Size}
	}
	if selected.name == "" {
		return Release{}, releaseAsset{}, fmt.Errorf("selfupdate: release %s has no exact asset %q", metadata.TagName, expectedAsset)
	}
	return Release{
		Version:     metadata.TagName,
		Name:        metadata.Name,
		Notes:       metadata.Body,
		URL:         metadata.HTMLURL,
		PublishedAt: metadata.PublishedAt,
	}, selected, nil
}

func parseAssetDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || !strings.HasPrefix(value, prefix) {
		return digest, errors.New("digest must be sha256 followed by 64 lowercase hexadecimal digits")
	}
	hexDigest := value[len(prefix):]
	for _, char := range hexDigest {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return digest, errors.New("digest must use lowercase hexadecimal digits")
		}
	}
	if _, err := hex.Decode(digest[:], []byte(hexDigest)); err != nil {
		return digest, errors.New("digest must use lowercase hexadecimal digits")
	}
	return digest, nil
}

// assetRedirectAllowed reports whether an asset-download redirect target is
// acceptable: HTTPS only, no credentials or fragment, and a host that is
// github.com or a *.githubusercontent.com asset host. allowHTTP relaxes the
// scheme and host checks for loopback test servers, mirroring validateURL.
func (u *Updater) assetRedirectAllowed(target *url.URL) error {
	if target.User != nil || target.Fragment != "" {
		return errors.New("selfupdate: unsafe release asset redirect rejected")
	}
	if u.allowHTTP {
		if target.Scheme != "https" && target.Scheme != "http" {
			return errors.New("selfupdate: unsafe release asset redirect rejected")
		}
		return nil
	}
	if target.Scheme != "https" || target.Port() != "" {
		return errors.New("selfupdate: unsafe release asset redirect rejected")
	}
	host := strings.ToLower(target.Hostname())
	if host != "github.com" && host != "githubusercontent.com" && !strings.HasSuffix(host, ".githubusercontent.com") {
		return errors.New("selfupdate: release asset redirect to an untrusted host rejected")
	}
	return nil
}

// idleTimeoutReader cancels its request context when a single Read makes no
// progress for longer than idle. It bounds stalls without capping the total
// transfer time of large downloads.
type idleTimeoutReader struct {
	reader io.Reader
	timer  *time.Timer // AfterFunc(idle, cancel), reset on every Read
	idle   time.Duration
}

func (r *idleTimeoutReader) Read(buffer []byte) (int, error) {
	r.timer.Reset(r.idle)
	n, err := r.reader.Read(buffer)
	r.timer.Reset(r.idle)
	return n, err
}

// countingReader wraps a reader, invoking report with the cumulative byte
// count after each successful read.
type countingReader struct {
	reader   io.Reader
	received int64
	total    int64
	report   func(received, total int64)
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 {
		r.received += int64(n)
		r.report(r.received, r.total)
	}
	return n, err
}

// downloadToFile fetches rawURL and streams the response body into file,
// hashing bytes as they are written so the digest is available without a
// second pass or a buffered copy. It mirrors download/doWithClient's
// redirect policy, Timeout=0 override, idle watchdog, non-2xx handling, and
// >limit overflow rejection; total enables progress reporting exactly as
// download does. The returned digest is the SHA-256 of exactly what was
// written to file.
func (u *Updater) downloadToFile(ctx context.Context, rawURL string, limit int64, description string, total int64, file *os.File) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := u.validateURL(rawURL, false); err != nil {
		return zero, fmt.Errorf("selfupdate: invalid %s URL: %w", description, err)
	}
	downloadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(downloadCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return zero, fmt.Errorf("selfupdate: create %s request: %w", description, err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "go-selfupdate")
	client := *u.httpClient
	client.Timeout = 0
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("selfupdate: too many release asset redirects")
		}
		return u.assetRedirectAllowed(request.URL)
	}
	timer := time.AfterFunc(u.downloadIdleTimeout, cancel)
	defer timer.Stop()

	response, err := client.Do(request)
	if err != nil {
		return zero, fmt.Errorf("selfupdate: fetch %s: %w", description, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, readErr := io.ReadAll(io.LimitReader(response.Body, maxErrorBytes+1))
		if readErr != nil {
			return zero, fmt.Errorf("selfupdate: fetch %s: HTTP %d (read error: %v)", description, response.StatusCode, readErr)
		}
		if int64(len(message)) > maxErrorBytes {
			message = message[:maxErrorBytes]
		}
		text := strings.TrimSpace(string(message))
		if text == "" {
			text = response.Status
		}
		return zero, fmt.Errorf("selfupdate: fetch %s: HTTP %d: %s", description, response.StatusCode, text)
	}
	if response.ContentLength > limit {
		return zero, fmt.Errorf("selfupdate: %s Content-Length %d exceeds the %d-byte limit", description, response.ContentLength, limit)
	}
	var bodyReader io.Reader = response.Body
	if u.downloadProgress != nil && total > 0 {
		bodyReader = &countingReader{reader: bodyReader, total: total, report: u.downloadProgress}
	}
	bodyReader = &idleTimeoutReader{reader: bodyReader, timer: timer, idle: u.downloadIdleTimeout}

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(bodyReader, limit+1))
	if err != nil {
		return zero, fmt.Errorf("selfupdate: read %s: %w", description, err)
	}
	if written > limit {
		return zero, fmt.Errorf("selfupdate: %s exceeds the %d-byte limit", description, limit)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (u *Updater) doWithClient(client *http.Client, request *http.Request, limit int64, description string, wrap func(io.Reader) io.Reader) ([]byte, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: fetch %s: %w", description, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, readErr := io.ReadAll(io.LimitReader(response.Body, maxErrorBytes+1))
		if readErr != nil {
			return nil, fmt.Errorf("selfupdate: fetch %s: HTTP %d (read error: %v)", description, response.StatusCode, readErr)
		}
		if int64(len(message)) > maxErrorBytes {
			message = message[:maxErrorBytes]
		}
		text := strings.TrimSpace(string(message))
		if text == "" {
			text = response.Status
		}
		return nil, &httpStatusError{description: description, statusCode: response.StatusCode, detail: text}
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("selfupdate: %s Content-Length %d exceeds the %d-byte limit", description, response.ContentLength, limit)
	}
	var bodyReader io.Reader = response.Body
	if wrap != nil {
		bodyReader = wrap(bodyReader)
	}
	body, err := io.ReadAll(io.LimitReader(bodyReader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("selfupdate: read %s: %w", description, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("selfupdate: %s exceeds the %d-byte limit", description, limit)
	}
	return body, nil
}

func (u *Updater) validateURL(rawURL string, api bool) error {
	if len(rawURL) == 0 || len(rawURL) > 4096 || strings.TrimSpace(rawURL) != rawURL || strings.ContainsAny(rawURL, "\x00\r\n") {
		return errors.New("URL is empty, too long, or contains invalid whitespace")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must be absolute and have no credentials or fragment")
	}
	if parsed.Scheme != "https" {
		if !u.allowHTTP || parsed.Scheme != "http" {
			return errors.New("URL must use HTTPS")
		}
	}
	if !u.allowHTTP {
		if api && !strings.EqualFold(parsed.Hostname(), "api.github.com") {
			return errors.New("API URL must use api.github.com")
		}
		if !api && !strings.EqualFold(parsed.Hostname(), "github.com") {
			return errors.New("release URLs must use github.com")
		}
	}
	if port := parsed.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return errors.New("URL has an invalid port")
		}
	}
	return nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("selfupdate: release metadata contains more than one JSON value")
		}
		return fmt.Errorf("selfupdate: decode trailing release metadata: %w", err)
	}
	return nil
}

func copyBounded(destination io.Writer, source io.Reader, limit int64, description string) (int64, error) {
	written, err := io.Copy(destination, io.LimitReader(source, limit+1))
	if err != nil {
		return written, fmt.Errorf("selfupdate: read %s: %w", description, err)
	}
	if written > limit {
		return written, fmt.Errorf("selfupdate: %s exceeds the %d-byte limit", description, limit)
	}
	return written, nil
}
