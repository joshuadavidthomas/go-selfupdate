// Package sigstore implements selfupdate.AttestationVerifier using Sigstore's
// public trust root. It is a separate package so that consumers who only use
// digest verification never link sigstore-go, its TUF client, and their
// transitive dependencies into their binary.
package sigstore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	selfupdate "github.com/joshuadavidthomas/go-selfupdate"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"golang.org/x/sync/singleflight"
)

const (
	inTotoStatementV1      = "https://in-toto.io/Statement/v1"
	trustedRootHTTPTimeout = 20 * time.Second
	trustedRootCachePeriod = 24 * time.Hour
)

// Verifier implements selfupdate.AttestationVerifier using Sigstore's public
// trust root and transparency log.
type Verifier struct {
	mu               sync.Mutex
	verifier         *verify.Verifier
	verifierExpires  time.Time
	initialize       singleflight.Group
	fetchTrustedRoot func() (root.TrustedMaterial, error)
}

// New returns a Verifier that checks attestation bundles against Sigstore's
// public trust root. The first verification fetches Sigstore TUF metadata
// with a 20-second deadline and no local TUF cache; a successful fetch caches
// the configured verifier in memory for 24 hours. The TUF client may finish
// an in-flight refresh after the calling context is canceled.
func New() *Verifier {
	return &Verifier{}
}

func buildCertificateIdentity(request selfupdate.AttestationRequest) (verify.CertificateIdentity, error) {
	sanMatcher, err := verify.NewSANMatcher(request.SignerIdentity, "")
	if err != nil {
		return verify.CertificateIdentity{}, err
	}
	issuerMatcher, err := verify.NewIssuerMatcher(request.Issuer, "")
	if err != nil {
		return verify.CertificateIdentity{}, err
	}
	return verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{
		SourceRepositoryURI:      request.SourceRepository,
		SourceRepositoryOwnerURI: request.SourceOwner,
	})
}

// VerifyAttestation implements selfupdate.AttestationVerifier.
func (v *Verifier) VerifyAttestation(ctx context.Context, bundleJSON []byte, request selfupdate.AttestationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var signedBundle bundle.Bundle
	if err := signedBundle.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("parse Sigstore bundle: %w", err)
	}
	identity, err := buildCertificateIdentity(request)
	if err != nil {
		return fmt.Errorf("build attestation identity policy: %w", err)
	}
	configured, err := v.configuredVerifier(ctx)
	if err != nil {
		return err
	}
	result, err := configured.Verify(&signedBundle, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", request.DigestSHA256[:]),
		verify.WithCertificateIdentity(identity),
	))
	if err != nil {
		return fmt.Errorf("verify Sigstore bundle: %w", err)
	}
	if result.Statement == nil || result.Statement.GetType() != inTotoStatementV1 {
		return errors.New("verified attestation is not an in-toto Statement v1")
	}
	if result.Statement.GetPredicateType() != request.PredicateType {
		return fmt.Errorf("verified attestation has predicate type %q", result.Statement.GetPredicateType())
	}
	digestHex := hex.EncodeToString(request.DigestSHA256[:])
	for _, subject := range result.Statement.GetSubject() {
		if subject.GetName() == request.AssetName && subject.GetDigest()["sha256"] == digestHex {
			return nil
		}
	}
	return fmt.Errorf("verified attestation has no exact subject named %q", request.AssetName)
}

func (v *Verifier) configuredVerifier(ctx context.Context) (*verify.Verifier, error) {
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

func (v *Verifier) cachedVerifier(now time.Time) *verify.Verifier {
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
