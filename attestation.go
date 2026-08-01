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
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/klauspost/compress/snappy"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"golang.org/x/sync/singleflight"
)

const (
	attestationIssuer       = "https://token.actions.githubusercontent.com"
	attestationPredicate    = "https://slsa.dev/provenance/v1"
	inTotoStatementV1       = "https://in-toto.io/Statement/v1"
	attestationBundleHost   = "tmaproduction.blob.core.windows.net"
	maxAttestationBytes     = int64(8 << 20)
	maxCompressedBundleSize = int64(4 << 20)
	maxAttestationPages     = 3
	maxAttestations         = 300
	trustedRootHTTPTimeout  = 20 * time.Second
	trustedRootCachePeriod  = 24 * time.Hour
)

type attestationVerificationPolicy struct {
	identity  string
	issuer    string
	predicate string
	assetName string
	digest    [sha256.Size]byte
}

type provenanceRecord struct {
	owner      string
	repository string
	workflow   string
	version    string
	assetName  string
	digest     [sha256.Size]byte
}

type attestationVerifier interface {
	Verify(context.Context, []byte, attestationVerificationPolicy) error
}

type sigstoreAttestationVerifier struct {
	mu               sync.Mutex
	verifier         *verify.Verifier
	verifierExpires  time.Time
	initialize       singleflight.Group
	fetchTrustedRoot func() (root.TrustedMaterial, error)
}

type githubAttestation struct {
	BundleURL string `json:"bundle_url"`
}

type githubAttestationsResponse struct {
	Attestations []githubAttestation `json:"attestations"`
}

func (u *Updater) verifyAttestation(ctx context.Context, release Release, asset releaseAsset) (*provenanceRecord, error) {
	policy := attestationVerificationPolicy{
		identity:  "https://github.com/" + u.owner + "/" + u.repository + "/" + u.attestationWorkflow + "@refs/tags/" + release.Version,
		issuer:    attestationIssuer,
		predicate: attestationPredicate,
		assetName: asset.name,
		digest:    asset.digest,
	}

	pageURL, err := u.attestationAPIURL(asset.digest)
	if err != nil {
		return nil, err
	}
	seen := 0
	var firstFailure error
	for page := 0; page < maxAttestationPages && pageURL != ""; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body, header, err := u.fetchAttestationPage(ctx, pageURL)
		if err != nil {
			return nil, err
		}
		var response githubAttestationsResponse
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(&response); err != nil {
			return nil, fmt.Errorf("selfupdate: decode attestation response: %w", err)
		}
		if err := ensureSingleJSONValue(decoder, "attestation response"); err != nil {
			return nil, err
		}
		if len(response.Attestations) > maxAttestations-seen {
			return nil, errors.New("selfupdate: attestation result limit exceeded")
		}
		seen += len(response.Attestations)

		for _, attestation := range response.Attestations {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if attestation.BundleURL == "" {
				firstFailure = keepFirstError(firstFailure, errors.New("attestation has no bundle URL"))
				continue
			}
			bundleJSON, fetchErr := u.fetchAttestationBundle(ctx, attestation.BundleURL)
			if fetchErr != nil {
				if isContextError(fetchErr) {
					return nil, fetchErr
				}
				firstFailure = keepFirstError(firstFailure, fmt.Errorf("external attestation bundle: %w", fetchErr))
			} else if verifyErr := u.attestationVerifier.Verify(ctx, bundleJSON, policy); verifyErr == nil {
				return u.newProvenanceRecord(release, asset), nil
			} else if isContextError(verifyErr) {
				return nil, verifyErr
			} else {
				firstFailure = keepFirstError(firstFailure, fmt.Errorf("external attestation bundle: %w", verifyErr))
			}
		}

		pageURL, err = u.nextAttestationPage(pageURL, header.Get("Link"))
		if err != nil {
			return nil, err
		}
	}
	if pageURL != "" {
		return nil, errors.New("selfupdate: attestation pagination limit exceeded")
	}
	if firstFailure != nil {
		return nil, fmt.Errorf("selfupdate: no valid artifact attestation for %s: %w", asset.name, firstFailure)
	}
	return nil, fmt.Errorf("selfupdate: no artifact attestations found for %s", asset.name)
}

func (u *Updater) newProvenanceRecord(release Release, asset releaseAsset) *provenanceRecord {
	return &provenanceRecord{
		owner:      u.owner,
		repository: u.repository,
		workflow:   u.attestationWorkflow,
		version:    release.Version,
		assetName:  asset.name,
		digest:     asset.digest,
	}
}

func (u *Updater) attestationAPIURL(digest [sha256.Size]byte) (string, error) {
	base, err := url.Parse(u.apiBaseURL)
	if err != nil || !base.IsAbs() || base.Host == "" || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return "", errors.New("selfupdate: invalid GitHub API base URL")
	}
	if err := u.validateURL(base.String(), true); err != nil {
		return "", err
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/repos/" + url.PathEscape(u.owner) + "/" + url.PathEscape(u.repository) + "/attestations/sha256:" + hex.EncodeToString(digest[:])
	base.RawQuery = "predicate_type=" + url.QueryEscape(attestationPredicate) + "&per_page=100"
	return base.String(), nil
}

func (u *Updater) fetchAttestationPage(ctx context.Context, pageURL string) ([]byte, http.Header, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("selfupdate: create attestation request: %w", err)
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
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("selfupdate: fetch attestation metadata: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("selfupdate: fetch attestation metadata: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxAttestationBytes {
		return nil, nil, fmt.Errorf("selfupdate: attestation response Content-Length exceeds the %d-byte limit", maxAttestationBytes)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAttestationBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("selfupdate: read attestation response: %w", err)
	}
	if int64(len(body)) > maxAttestationBytes {
		return nil, nil, fmt.Errorf("selfupdate: attestation response exceeds the %d-byte limit", maxAttestationBytes)
	}
	return body, response.Header.Clone(), nil
}

func (u *Updater) nextAttestationPage(current, linkHeader string) (string, error) {
	if strings.TrimSpace(linkHeader) == "" {
		return "", nil
	}
	var next string
	for _, part := range strings.Split(linkHeader, ",") {
		sections := strings.Split(part, ";")
		if len(sections) < 2 {
			return "", errors.New("selfupdate: malformed attestation pagination link")
		}
		isNext := false
		for _, section := range sections[1:] {
			if strings.TrimSpace(section) == `rel="next"` {
				isNext = true
			}
		}
		if !isNext {
			continue
		}
		value := strings.TrimSpace(sections[0])
		if len(value) < 3 || value[0] != '<' || value[len(value)-1] != '>' || next != "" {
			return "", errors.New("selfupdate: malformed attestation next-page link")
		}
		next = value[1 : len(value)-1]
	}
	if next == "" {
		return "", nil
	}
	currentURL, err := url.Parse(current)
	if err != nil {
		return "", errors.New("selfupdate: invalid current attestation page URL")
	}
	nextURL, err := url.Parse(next)
	if err != nil {
		return "", errors.New("selfupdate: invalid attestation next-page URL")
	}
	if !nextURL.IsAbs() {
		nextURL = currentURL.ResolveReference(nextURL)
	}
	if len(nextURL.String()) > 4096 || nextURL.Scheme != currentURL.Scheme || !strings.EqualFold(nextURL.Host, currentURL.Host) || nextURL.Path != currentURL.Path || nextURL.EscapedPath() != currentURL.EscapedPath() || nextURL.User != nil || nextURL.Fragment != "" || nextURL.Opaque != "" {
		return "", errors.New("selfupdate: unsafe attestation next-page URL")
	}
	query := nextURL.Query()
	if query.Get("predicate_type") != attestationPredicate || query.Get("per_page") != "100" || query.Get("before") == "" {
		return "", errors.New("selfupdate: attestation next-page query changed required parameters")
	}
	for key, values := range query {
		if (key != "predicate_type" && key != "per_page" && key != "before") || len(values) != 1 {
			return "", errors.New("selfupdate: unsafe attestation next-page query")
		}
	}
	return nextURL.String(), nil
}

func (u *Updater) fetchAttestationBundle(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || len(rawURL) == 0 || len(rawURL) > 4096 || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("selfupdate: unsafe attestation bundle URL")
	}
	if parsed.Scheme != "https" && (!u.allowHTTP || parsed.Scheme != "http") {
		return nil, errors.New("selfupdate: attestation bundle URL must use HTTPS")
	}
	if !strings.EqualFold(parsed.Hostname(), u.attestationBundleHost) || (!u.allowHTTP && parsed.Port() != "") {
		return nil, errors.New("selfupdate: attestation bundle URL uses an untrusted host")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: create attestation bundle request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "go-selfupdate")
	request.Header.Del("Authorization")

	client := *u.httpClient
	client.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
		if request.Header.Get("Authorization") != "" {
			return errors.New("selfupdate: authorization on attestation bundle redirect rejected")
		}
		target := request.URL
		if target.Scheme != "https" || target.User != nil || target.Fragment != "" || !strings.EqualFold(target.Hostname(), u.attestationBundleHost) || target.Port() != "" {
			return errors.New("selfupdate: unsafe attestation bundle redirect rejected")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// Transport and redirect errors can contain the signed Azure URL. Do not
		// copy its query string into an error returned to the caller.
		return nil, errors.New("selfupdate: fetch attestation bundle: request failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("selfupdate: fetch attestation bundle: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxCompressedBundleSize {
		return nil, fmt.Errorf("selfupdate: compressed attestation bundle exceeds the %d-byte limit", maxCompressedBundleSize)
	}
	compressed, err := io.ReadAll(io.LimitReader(response.Body, maxCompressedBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("selfupdate: read attestation bundle: %w", err)
	}
	if int64(len(compressed)) > maxCompressedBundleSize {
		return nil, fmt.Errorf("selfupdate: compressed attestation bundle exceeds the %d-byte limit", maxCompressedBundleSize)
	}
	decodedLength, err := snappy.DecodedLen(compressed)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: decode attestation bundle framing: %w", err)
	}
	if int64(decodedLength) > maxAttestationBytes {
		return nil, fmt.Errorf("selfupdate: attestation bundle exceeds the %d-byte limit", maxAttestationBytes)
	}
	decoded, err := snappy.Decode(nil, compressed)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: decompress attestation bundle: %w", err)
	}
	return decoded, nil
}

func (v *sigstoreAttestationVerifier) Verify(ctx context.Context, bundleJSON []byte, policy attestationVerificationPolicy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var signedBundle bundle.Bundle
	if err := signedBundle.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("parse Sigstore bundle: %w", err)
	}
	identity, err := verify.NewShortCertificateIdentity(policy.issuer, "", policy.identity, "")
	if err != nil {
		return fmt.Errorf("build attestation identity policy: %w", err)
	}
	configured, err := v.configuredVerifier(ctx)
	if err != nil {
		return err
	}
	result, err := configured.Verify(&signedBundle, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", policy.digest[:]),
		verify.WithCertificateIdentity(identity),
	))
	if err != nil {
		return fmt.Errorf("verify Sigstore bundle: %w", err)
	}
	if result.Statement == nil || result.Statement.GetType() != inTotoStatementV1 {
		return errors.New("verified attestation is not an in-toto Statement v1")
	}
	if result.Statement.GetPredicateType() != policy.predicate {
		return fmt.Errorf("verified attestation has predicate type %q", result.Statement.GetPredicateType())
	}
	digestHex := hex.EncodeToString(policy.digest[:])
	for _, subject := range result.Statement.GetSubject() {
		if subject.GetName() == policy.assetName && subject.GetDigest()["sha256"] == digestHex {
			return nil
		}
	}
	return fmt.Errorf("verified attestation has no exact subject named %q", policy.assetName)
}

func (v *sigstoreAttestationVerifier) configuredVerifier(ctx context.Context) (*verify.Verifier, error) {
	if configured := v.cachedVerifier(time.Now()); configured != nil {
		return configured, nil
	}
	result := v.initialize.DoChan("public-root", func() (any, error) {
		if configured := v.cachedVerifier(time.Now()); configured != nil {
			return configured, nil
		}
		fetchTrustedRoot := v.fetchTrustedRoot
		if fetchTrustedRoot == nil {
			fetchTrustedRoot = fetchPublicTrustedRoot
		}
		trustedRoot, err := fetchTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("initialize public Sigstore verifier: %w", err)
		}
		configured, err := verify.NewVerifier(trustedRoot,
			verify.WithSignedCertificateTimestamps(1),
			verify.WithTransparencyLog(1),
			verify.WithObserverTimestamps(1),
			verify.WithoutStatementPredicate(),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize public Sigstore verifier: %w", err)
		}
		v.mu.Lock()
		v.verifier = configured
		v.verifierExpires = time.Now().Add(trustedRootCachePeriod)
		v.mu.Unlock()
		return configured, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case outcome := <-result:
		if outcome.Err != nil {
			return nil, outcome.Err
		}
		return outcome.Val.(*verify.Verifier), nil
	}
}

func (v *sigstoreAttestationVerifier) cachedVerifier(now time.Time) *verify.Verifier {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier == nil || !now.Before(v.verifierExpires) {
		return nil
	}
	return v.verifier
}

func fetchPublicTrustedRoot() (root.TrustedMaterial, error) {
	options := tuf.DefaultOptions().WithDisableLocalCache()
	tufFetcher := fetcher.NewDefaultFetcher()
	tufFetcher.SetHTTPClient(&deadlineHTTPClient{
		deadline: time.Now().Add(trustedRootHTTPTimeout),
		client: &http.Client{
			Timeout: trustedRootHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("sigstore TUF redirect rejected")
			},
		},
	})
	options.Fetcher = tufFetcher
	return root.FetchTrustedRootWithOptions(options)
}

type deadlineHTTPClient struct {
	client   *http.Client
	deadline time.Time
}

func (c *deadlineHTTPClient) Do(request *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithDeadline(request.Context(), c.deadline)
	response, err := c.client.Do(request.Clone(ctx))
	if response == nil || response.Body == nil {
		cancel()
	} else {
		response.Body = &cancelReadCloser{ReadCloser: response.Body, cancel: cancel}
	}
	return response, err
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelReadCloser) Close() error {
	r.cancel()
	return r.ReadCloser.Close()
}

func keepFirstError(first, candidate error) error {
	if first != nil {
		return first
	}
	return candidate
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func ensureSingleJSONValue(decoder *json.Decoder, description string) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("selfupdate: %s contains more than one JSON value", description)
		}
		return fmt.Errorf("selfupdate: decode trailing %s: %w", description, err)
	}
	return nil
}

func (p provenanceRecord) matches(u *Updater, plan *Plan) bool {
	return p.owner == u.owner &&
		p.repository == u.repository &&
		p.workflow == u.attestationWorkflow &&
		p.version == plan.availableVersion &&
		p.assetName == plan.assetName &&
		p.digest == plan.archiveDigest
}

func validateAttestationWorkflow(workflow string) error {
	const prefix = ".github/workflows/"
	if len(workflow) > 255 || !strings.HasPrefix(workflow, prefix) {
		return errors.New("selfupdate: attestation signer workflow must be .github/workflows/<filename>.yml or .yaml")
	}
	filename := strings.TrimPrefix(workflow, prefix)
	if filename == "" || strings.ContainsAny(filename, "/\\:\x00\r\n\t") || strings.TrimSpace(filename) != filename {
		return errors.New("selfupdate: attestation signer workflow must contain one canonical filename")
	}
	for _, char := range filename {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return errors.New("selfupdate: attestation signer workflow must not contain whitespace or control characters")
		}
	}
	if !strings.HasSuffix(filename, ".yml") && !strings.HasSuffix(filename, ".yaml") {
		return errors.New("selfupdate: attestation signer workflow must end in .yml or .yaml")
	}
	base := strings.TrimSuffix(strings.TrimSuffix(filename, ".yaml"), ".yml")
	if base == "" || base == "." || base == ".." {
		return errors.New("selfupdate: attestation signer workflow filename is empty or a dot segment")
	}
	return nil
}
