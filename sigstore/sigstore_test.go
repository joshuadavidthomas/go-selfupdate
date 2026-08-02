package sigstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	selfupdate "github.com/joshuadavidthomas/go-selfupdate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoretest "github.com/sigstore/sigstore-go/pkg/testing/data"
)

func TestBuildCertificateIdentity(t *testing.T) {
	t.Parallel()
	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		request := selfupdate.AttestationRequest{
			SignerIdentity:   "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			Issuer:           "https://token.actions.githubusercontent.com",
			SourceRepository: "https://github.com/owner/repo",
			SourceOwner:      "https://github.com/owner",
		}
		identity, err := buildCertificateIdentity(request)
		if err != nil {
			t.Fatalf("buildCertificateIdentity: %v", err)
		}
		if identity.SubjectAlternativeName.SubjectAlternativeName != request.SignerIdentity {
			t.Errorf("SAN = %q, want %q", identity.SubjectAlternativeName.SubjectAlternativeName, request.SignerIdentity)
		}
		if identity.Issuer.Issuer != request.Issuer {
			t.Errorf("issuer = %q, want %q", identity.Issuer.Issuer, request.Issuer)
		}
		if identity.SourceRepositoryURI != request.SourceRepository {
			t.Errorf("source repository = %q, want %q", identity.SourceRepositoryURI, request.SourceRepository)
		}
		if identity.SourceRepositoryOwnerURI != request.SourceOwner {
			t.Errorf("source owner = %q, want %q", identity.SourceRepositoryOwnerURI, request.SourceOwner)
		}
	})

	t.Run("empty identity", func(t *testing.T) {
		t.Parallel()
		_, err := buildCertificateIdentity(selfupdate.AttestationRequest{Issuer: "https://token.actions.githubusercontent.com"})
		if err == nil {
			t.Fatal("buildCertificateIdentity accepted an empty identity")
		}
	})

	t.Run("empty issuer", func(t *testing.T) {
		t.Parallel()
		_, err := buildCertificateIdentity(selfupdate.AttestationRequest{
			SignerIdentity: "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
		})
		if err == nil {
			t.Fatal("buildCertificateIdentity accepted an empty issuer")
		}
	})
}

func TestSigstoreTrustedRootInitializationRetriesAfterFailure(t *testing.T) {
	entity := sigstoretest.Bundle(t, "othername.sigstore.json")
	bundleJSON, err := entity.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	trustedRoot := sigstoretest.TrustedRoot(t, "scaffolding.json")
	var fetches atomic.Int32
	verifier := &Verifier{fetchTrustedRoot: func() (root.TrustedMaterial, error) {
		if fetches.Add(1) == 1 {
			return nil, errors.New("temporary failure")
		}
		return trustedRoot, nil
	}}
	digestBytes, err := hex.DecodeString("bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b")
	if err != nil {
		t.Fatal(err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	request := selfupdate.AttestationRequest{
		Issuer: "http://oidc.local:8080", SignerIdentity: "foo!oidc.local",
		PredicateType: "https://slsa.dev/provenance/v1", AssetName: "artifact", DigestSHA256: digest,
	}
	if err := verifier.VerifyAttestation(context.Background(), bundleJSON, request); err == nil || !strings.Contains(err.Error(), "temporary failure") {
		t.Fatalf("first VerifyAttestation error = %v", err)
	}
	if err := verifier.VerifyAttestation(context.Background(), bundleJSON, request); err == nil || !strings.Contains(err.Error(), "not an in-toto Statement v1") {
		t.Fatalf("second VerifyAttestation error = %v", err)
	}
	if fetches.Load() != 2 {
		t.Fatalf("trusted root fetches = %d", fetches.Load())
	}
}

func TestSigstoreAttestationVerifierRejectsParsingAndPolicyFailures(t *testing.T) {
	t.Run("parse before trusted root fetch", func(t *testing.T) {
		var fetches atomic.Int32
		verifier := &Verifier{fetchTrustedRoot: func() (root.TrustedMaterial, error) {
			fetches.Add(1)
			return nil, errors.New("must not fetch")
		}}
		err := verifier.VerifyAttestation(context.Background(), []byte(`{"bad":true}`), selfupdate.AttestationRequest{})
		if err == nil || !strings.Contains(err.Error(), "parse Sigstore bundle") {
			t.Fatalf("VerifyAttestation error = %v", err)
		}
		if fetches.Load() != 0 {
			t.Fatalf("trusted root fetches = %d", fetches.Load())
		}
	})

	t.Run("actual cryptography then statement policy", func(t *testing.T) {
		entity := sigstoretest.Bundle(t, "othername.sigstore.json")
		bundleJSON, err := entity.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		trustedRoot := sigstoretest.TrustedRoot(t, "scaffolding.json")
		verifier := &Verifier{fetchTrustedRoot: func() (root.TrustedMaterial, error) {
			return trustedRoot, nil
		}}
		digestBytes, err := hex.DecodeString("bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b")
		if err != nil {
			t.Fatal(err)
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		err = verifier.VerifyAttestation(context.Background(), bundleJSON, selfupdate.AttestationRequest{
			Issuer: "http://oidc.local:8080", SignerIdentity: "foo!oidc.local",
			PredicateType: "https://slsa.dev/provenance/v1", AssetName: "artifact", DigestSHA256: digest,
		})
		if err == nil || !strings.Contains(err.Error(), "not an in-toto Statement v1") {
			t.Fatalf("VerifyAttestation error = %v", err)
		}
	})
}
