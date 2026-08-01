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
}

func (u *Updater) fetchLatestRelease(ctx context.Context, expectedAsset string) (Release, releaseAsset, error) {
	base, err := url.Parse(u.apiBaseURL)
	if err != nil || !base.IsAbs() || base.Host == "" || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return Release{}, releaseAsset{}, errors.New("selfupdate: invalid GitHub API base URL")
	}
	if err := u.validateURL(base.String(), true); err != nil {
		return Release{}, releaseAsset{}, err
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/repos/" + url.PathEscape(u.owner) + "/" + url.PathEscape(u.repository) + "/releases/latest"

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
	body, err := u.doWithClient(&client, request, maxMetadataBytes, "release metadata")
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
		selected = releaseAsset{name: asset.Name, downloadURL: asset.DownloadURL, digest: digest}
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

func (u *Updater) download(ctx context.Context, rawURL string, limit int64, description string) ([]byte, error) {
	if err := u.validateURL(rawURL, false); err != nil {
		return nil, fmt.Errorf("selfupdate: invalid %s URL: %w", description, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: create %s request: %w", description, err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "go-selfupdate")
	return u.do(request, limit, description)
}

func (u *Updater) do(request *http.Request, limit int64, description string) ([]byte, error) {
	return u.doWithClient(u.httpClient, request, limit, description)
}

func (u *Updater) doWithClient(client *http.Client, request *http.Request, limit int64, description string) ([]byte, error) {
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
		return nil, fmt.Errorf("selfupdate: fetch %s: HTTP %d: %s", description, response.StatusCode, text)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("selfupdate: %s Content-Length %d exceeds the %d-byte limit", description, response.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
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
