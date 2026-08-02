package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/snappy"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoretest "github.com/sigstore/sigstore-go/pkg/testing/data"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type stubAttestationVerifier struct {
	mu       sync.Mutex
	calls    int
	bundles  [][]byte
	policies []attestationVerificationPolicy
	verify   func(context.Context, []byte, attestationVerificationPolicy) error
}

func (v *stubAttestationVerifier) Verify(ctx context.Context, bundle []byte, policy attestationVerificationPolicy) error {
	v.mu.Lock()
	v.calls++
	v.bundles = append(v.bundles, bytes.Clone(bundle))
	v.policies = append(v.policies, policy)
	v.mu.Unlock()
	if v.verify != nil {
		return v.verify(ctx, bundle, policy)
	}
	return nil
}

func (v *stubAttestationVerifier) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

type attestationTestServer struct {
	updater             *Updater
	server              *httptest.Server
	archiveRequests     atomic.Int32
	attestationRequests atomic.Int32
	archiveDigest       [sha256.Size]byte
	bundleBodies        map[string][]byte
}

func newAttestationTestServer(t *testing.T, policy *AttestationPolicy, token string, verifier attestationVerifier, attestationHandler http.HandlerFunc) *attestationTestServer {
	t.Helper()
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	fixture := &attestationTestServer{
		archiveDigest: sha256.Sum256(archive),
		bundleBodies:  map[string][]byte{"": []byte(`{"bundle":"valid"}`)},
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/owner/repo/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v2.0.0", "name": "Release v2.0.0", "body": "notes",
				"html_url": fixture.server.URL + "/release", "published_at": "2026-01-02T03:04:05Z",
				"assets": []map[string]any{{
					"name": "tool_linux_amd64.tar.gz", "browser_download_url": fixture.server.URL + "/asset",
					"size": len(archive), "digest": fmt.Sprintf("sha256:%x", fixture.archiveDigest),
				}},
			})
		case strings.HasPrefix(r.URL.Path, "/repos/owner/repo/attestations/"):
			fixture.attestationRequests.Add(1)
			attestationHandler(w, r)
		case r.URL.Path == "/blob":
			if r.Header.Get("Authorization") != "" {
				t.Errorf("bundle Authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write(snappy.Encode(nil, fixture.bundleBodies[r.URL.Query().Get("id")]))
		case r.URL.Path == "/asset":
			fixture.archiveRequests.Add(1)
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.server.Close)

	u, err := New(Config{
		Repository: "owner/repo", Command: "tool", CurrentVersion: "v1.0.0",
		GitHubToken: token, Attestation: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	u.apiBaseURL = fixture.server.URL
	u.allowHTTP = true
	serverURL, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.attestationBundleHost = serverURL.Hostname()
	u.goos, u.goarch = "linux", "amd64"
	u.executablePath = func() (string, error) { return target, nil }
	if verifier != nil {
		u.attestationVerifier = verifier
	}
	fixture.updater = u
	return fixture
}

func testBundleAttestation(fixture *attestationTestServer, id string) githubAttestation {
	return githubAttestation{BundleURL: fixture.server.URL + "/blob?id=" + url.QueryEscape(id) + "&sig=signed-secret"}
}

func writeAttestations(t *testing.T, w http.ResponseWriter, attestations []githubAttestation) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(githubAttestationsResponse{Attestations: attestations}); err != nil {
		t.Errorf("encode attestations: %v", err)
	}
}

func TestValidateAttestationWorkflow(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		workflow string
		valid    bool
	}{
		{".github/workflows/release.yml", true},
		{".github/workflows/attest.yaml", true},
		{"release.yml", false},
		{".github/workflows/.yml", false},
		{".github/workflows/release.YML", false},
		{".github/workflows/sub/release.yml", false},
		{".github/workflows/../release.yml", false},
		{".github/workflows/release.yml ", false},
		{".github/workflows/release name.yml", false},
		{".github/workflows/release.yml/other", false},
		{".github\\workflows\\release.yml", false},
		{".github/workflows/release.yml\n", false},
		{strings.Repeat("a", 256), false},
	} {
		name := strings.ReplaceAll(test.workflow, "/", "_")
		t.Run(name, func(t *testing.T) {
			err := validateAttestationWorkflow(test.workflow)
			if (err == nil) != test.valid {
				t.Fatalf("validateAttestationWorkflow(%q) = %v, valid=%v", test.workflow, err, test.valid)
			}
		})
	}
}

func TestCheckWithoutAttestationPolicyMakesNoAttestationRequest(t *testing.T) {
	fixture := newAttestationTestServer(t, nil, "", nil, func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected attestation request")
	})
	if _, err := fixture.updater.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if fixture.attestationRequests.Load() != 0 {
		t.Fatalf("attestation requests = %d", fixture.attestationRequests.Load())
	}
}

func TestCheckAttestationRequestAndVerifiedPlan(t *testing.T) {
	verifier := &stubAttestationVerifier{}
	var fixture *attestationTestServer
	fixture = newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "secret", verifier, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/repos/owner/repo/attestations/sha256:" + hex.EncodeToString(fixture.archiveDigest[:])
		if r.Method != http.MethodGet || r.URL.Path != wantPath {
			t.Errorf("request = %s %s, want GET %s", r.Method, r.URL.Path, wantPath)
		}
		if r.URL.Query().Get("predicate_type") != attestationPredicate || r.URL.Query().Get("per_page") != "100" || len(r.URL.Query()) != 2 {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("headers = %#v", r.Header)
		}
		writeAttestations(t, w, []githubAttestation{testBundleAttestation(fixture, "")})
	})

	plan, err := fixture.updater.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if plan.provenance == nil || !plan.provenance.matches(fixture.updater, plan) {
		t.Fatal("plan has no matching provenance")
	}
	if verifier.callCount() != 1 {
		t.Fatalf("verifier calls = %d", verifier.callCount())
	}
	verifier.mu.Lock()
	gotPolicy := verifier.policies[0]
	verifier.mu.Unlock()
	wantIdentity := "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v2.0.0"
	if gotPolicy.identity != wantIdentity || gotPolicy.issuer != attestationIssuer || gotPolicy.predicate != attestationPredicate || gotPolicy.assetName != "tool_linux_amd64.tar.gz" || gotPolicy.digest != fixture.archiveDigest {
		t.Fatalf("verification policy = %#v", gotPolicy)
	}
}

func TestCheckAttestationFailuresPrecedeArchiveDownload(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		verify  func(context.Context, []byte, attestationVerificationPolicy) error
		want    string
	}{
		{
			name: "missing",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeAttestations(t, w, nil)
			},
			want: "no artifact attestations found",
		},
		{
			name: "malformed",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"attestations":`))
			},
			want: "decode attestation response",
		},
		{
			name: "oversized metadata",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", fmt.Sprint(maxAttestationBytes+1))
				w.WriteHeader(http.StatusOK)
			},
			want: "Content-Length",
		},
		{
			name: "invalid verification",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeAttestations(t, w, []githubAttestation{{BundleURL: "http://" + r.Host + "/blob"}})
			},
			verify: func(context.Context, []byte, attestationVerificationPolicy) error {
				return errors.New("signature rejected")
			},
			want: "signature rejected",
		},
		{
			name: "no bundle",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeAttestations(t, w, []githubAttestation{{}})
			},
			want: "no bundle URL",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := &stubAttestationVerifier{verify: test.verify}
			fixture := newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "", verifier, test.handler)
			_, err := fixture.updater.Check(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Check error = %v, want %q", err, test.want)
			}
			if fixture.archiveRequests.Load() != 0 {
				t.Fatalf("archive requests = %d", fixture.archiveRequests.Load())
			}
		})
	}
}

func TestCheckAttestationCancellation(t *testing.T) {
	started := make(chan struct{})
	fixture := newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "", &stubAttestationVerifier{}, func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := fixture.updater.Check(ctx)
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Check error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Check did not return after attestation request cancellation")
	}
	if fixture.archiveRequests.Load() != 0 {
		t.Fatalf("archive requests = %d", fixture.archiveRequests.Load())
	}
}

func TestCheckAcceptsValidAttestationAmongUnrelatedBundles(t *testing.T) {
	verifier := &stubAttestationVerifier{verify: func(_ context.Context, bundle []byte, _ attestationVerificationPolicy) error {
		if bytes.Contains(bundle, []byte(`"valid"`)) {
			return nil
		}
		return errors.New("unrelated")
	}}
	var fixture *attestationTestServer
	fixture = newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "", verifier, func(w http.ResponseWriter, _ *http.Request) {
		writeAttestations(t, w, []githubAttestation{
			testBundleAttestation(fixture, "unrelated"),
			testBundleAttestation(fixture, "valid"),
		})
	})
	fixture.bundleBodies["unrelated"] = []byte(`{"kind":"unrelated"}`)
	fixture.bundleBodies["valid"] = []byte(`{"kind":"valid"}`)
	if _, err := fixture.updater.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if verifier.callCount() != 2 {
		t.Fatalf("verifier calls = %d", verifier.callCount())
	}
}

func TestAttestationRedirectsAndBundleErrorsAreSafe(t *testing.T) {
	t.Run("metadata redirect", func(t *testing.T) {
		var redirected atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			redirected.Add(1)
		}))
		defer target.Close()
		fixture := newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "secret", &stubAttestationVerifier{}, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		})
		_, err := fixture.updater.Check(context.Background())
		if err == nil || !strings.Contains(err.Error(), "redirect rejected") {
			t.Fatalf("Check error = %v", err)
		}
		if redirected.Load() != 0 {
			t.Fatalf("redirect target requests = %d", redirected.Load())
		}
	})

	t.Run("signed query hidden on transport error", func(t *testing.T) {
		u := mustUpdater(t, "v1.0.0")
		u.allowHTTP = true
		u.attestationBundleHost = "bundle.example"
		u.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("transport rejected %s", request.URL.String())
		})}
		_, err := u.fetchAttestationBundle(context.Background(), "http://bundle.example/archive?sig=signed-secret")
		if err == nil || !strings.Contains(err.Error(), "request failed") || strings.Contains(err.Error(), "signed-secret") {
			t.Fatalf("fetchAttestationBundle error = %v", err)
		}
	})

	t.Run("bundle redirect", func(t *testing.T) {
		var redirectTargetRequests atomic.Int32
		secondServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			redirectTargetRequests.Add(1)
		}))
		defer secondServer.Close()

		firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/blob" {
				http.Redirect(w, r, secondServer.URL, http.StatusFound)
				return
			}
			http.NotFound(w, r)
		}))
		defer firstServer.Close()

		u := mustUpdater(t, "v1.0.0")
		u.allowHTTP = true
		firstURL, err := url.Parse(firstServer.URL)
		if err != nil {
			t.Fatal(err)
		}
		u.attestationBundleHost = firstURL.Hostname()

		_, err = u.fetchAttestationBundle(context.Background(), firstServer.URL+"/blob?sig=signed-secret")
		if err == nil || !strings.Contains(err.Error(), "request failed") || strings.Contains(err.Error(), "signed-secret") {
			t.Fatalf("fetchAttestationBundle error = %v", err)
		}
		if redirectTargetRequests.Load() != 0 {
			t.Fatalf("redirect target requests = %d", redirectTargetRequests.Load())
		}
	})
}

func TestAttestationBundleURLSafetyAndSnappyBounds(t *testing.T) {
	t.Run("unsafe URL", func(t *testing.T) {
		fixture := newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "", &stubAttestationVerifier{}, func(w http.ResponseWriter, _ *http.Request) {
			writeAttestations(t, w, []githubAttestation{{BundleURL: "https://example.com/bundle?sig=secret"}})
		})
		_, err := fixture.updater.Check(context.Background())
		if err == nil || !strings.Contains(err.Error(), "untrusted host") || strings.Contains(err.Error(), "sig=secret") {
			t.Fatalf("Check error = %v", err)
		}
	})

	for _, test := range []struct {
		name       string
		decoded    []byte
		wantError  string
		verifyCall int
	}{
		{"valid", []byte(`{"bundle":"valid"}`), "", 1},
		{"decoded limit", bytes.Repeat([]byte("x"), int(maxAttestationBytes)+1), "attestation bundle exceeds", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := &stubAttestationVerifier{}
			var fixture *attestationTestServer
			fixture = newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "secret", verifier, func(w http.ResponseWriter, _ *http.Request) {
				writeAttestations(t, w, []githubAttestation{testBundleAttestation(fixture, "")})
			})
			fixture.bundleBodies[""] = test.decoded
			_, err := fixture.updater.Check(context.Background())
			if test.wantError == "" && err != nil {
				t.Fatalf("Check: %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("Check error = %v, want %q", err, test.wantError)
			}
			if verifier.callCount() != test.verifyCall {
				t.Fatalf("verifier calls = %d, want %d", verifier.callCount(), test.verifyCall)
			}
		})
	}
}

func TestAttestationPagination(t *testing.T) {
	t.Run("production before cursor", func(t *testing.T) {
		verifier := &stubAttestationVerifier{}
		var fixture *attestationTestServer
		fixture = newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "", verifier, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("before") == "" {
				next := fixture.server.URL + r.URL.Path + "?before=cursor&per_page=100&predicate_type=" + url.QueryEscape(attestationPredicate)
				w.Header().Set("Link", "<"+next+">; rel=\"next\"")
				writeAttestations(t, w, nil)
				return
			}
			writeAttestations(t, w, []githubAttestation{testBundleAttestation(fixture, "")})
		})
		if _, err := fixture.updater.Check(context.Background()); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if fixture.attestationRequests.Load() != 2 {
			t.Fatalf("attestation requests = %d", fixture.attestationRequests.Load())
		}
	})

	t.Run("page bound", func(t *testing.T) {
		var fixture *attestationTestServer
		fixture = newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "", &stubAttestationVerifier{}, func(w http.ResponseWriter, r *http.Request) {
			next := fixture.server.URL + r.URL.Path + "?before=cursor&per_page=100&predicate_type=" + url.QueryEscape(attestationPredicate)
			w.Header().Set("Link", "<"+next+">; rel=\"next\"")
			writeAttestations(t, w, nil)
		})
		_, err := fixture.updater.Check(context.Background())
		if err == nil || !strings.Contains(err.Error(), "pagination limit") {
			t.Fatalf("Check error = %v", err)
		}
		if fixture.attestationRequests.Load() != maxAttestationPages {
			t.Fatalf("attestation requests = %d", fixture.attestationRequests.Load())
		}
	})

	t.Run("result bound", func(t *testing.T) {
		fixture := newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "", &stubAttestationVerifier{}, func(w http.ResponseWriter, _ *http.Request) {
			writeAttestations(t, w, make([]githubAttestation, maxAttestations+1))
		})
		_, err := fixture.updater.Check(context.Background())
		if err == nil || !strings.Contains(err.Error(), "result limit") {
			t.Fatalf("Check error = %v", err)
		}
	})
}

func TestNextAttestationPageRejectsUnsafeLinks(t *testing.T) {
	u := mustUpdater(t, "v1.0.0")
	current := "https://api.github.com/repos/owner/repo/attestations/sha256:abc?predicate_type=" + url.QueryEscape(attestationPredicate) + "&per_page=100"
	for _, next := range []string{
		"https://evil.example/repos/owner/repo/attestations/sha256:abc?before=x&per_page=100&predicate_type=" + url.QueryEscape(attestationPredicate),
		"https://api.github.com/repos/owner/repo/other?before=x&per_page=100&predicate_type=" + url.QueryEscape(attestationPredicate),
		"https://api.github.com/repos/owner/repo/attestations/sha256:abc?after=x&per_page=100&predicate_type=" + url.QueryEscape(attestationPredicate),
		"https://api.github.com/repos/owner/repo/attestations/sha256:abc?before=x&per_page=99&predicate_type=" + url.QueryEscape(attestationPredicate),
		"https://api.github.com/repos/owner/repo/attestations/sha256:abc?before=x&before=y&per_page=100&predicate_type=" + url.QueryEscape(attestationPredicate),
		"https://user@api.github.com/repos/owner/repo/attestations/sha256:abc?before=x&per_page=100&predicate_type=" + url.QueryEscape(attestationPredicate),
	} {
		if _, err := u.nextAttestationPage(current, "<"+next+">; rel=\"next\""); err == nil {
			t.Errorf("accepted unsafe next link %q", next)
		}
	}
	if _, err := u.nextAttestationPage(current, "not-a-link; rel=\"next\""); err == nil {
		t.Error("accepted malformed Link header")
	}
}

func TestApplyRequiresMatchingProvenanceBeforeDownload(t *testing.T) {
	var fixture *attestationTestServer
	fixture = newAttestationTestServer(t, &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"}, "", &stubAttestationVerifier{}, func(w http.ResponseWriter, _ *http.Request) {
		writeAttestations(t, w, []githubAttestation{testBundleAttestation(fixture, "")})
	})
	plan, err := fixture.updater.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	verified := plan.provenance
	plan.provenance = nil
	if _, err := fixture.updater.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "matching verified provenance") {
		t.Fatalf("Apply without provenance error = %v", err)
	}
	mismatched := *verified
	mismatched.assetName = "other.tar.gz"
	plan.provenance = &mismatched
	if _, err := fixture.updater.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "matching verified provenance") {
		t.Fatalf("Apply with mismatched provenance error = %v", err)
	}
	if fixture.archiveRequests.Load() != 0 {
		t.Fatalf("archive requests = %d", fixture.archiveRequests.Load())
	}
}

func TestSigstoreTrustedRootInitializationRetriesAfterFailure(t *testing.T) {
	entity := sigstoretest.Bundle(t, "othername.sigstore.json")
	bundleJSON, err := entity.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	trustedRoot := sigstoretest.TrustedRoot(t, "scaffolding.json")
	var fetches atomic.Int32
	verifier := &sigstoreAttestationVerifier{fetchTrustedRoot: func() (root.TrustedMaterial, error) {
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
	policy := attestationVerificationPolicy{
		issuer: "http://oidc.local:8080", identity: "foo!oidc.local",
		predicate: attestationPredicate, assetName: "artifact", digest: digest,
	}
	if err := verifier.Verify(context.Background(), bundleJSON, policy); err == nil || !strings.Contains(err.Error(), "temporary failure") {
		t.Fatalf("first Verify error = %v", err)
	}
	if err := verifier.Verify(context.Background(), bundleJSON, policy); err == nil || !strings.Contains(err.Error(), "not an in-toto Statement v1") {
		t.Fatalf("second Verify error = %v", err)
	}
	if fetches.Load() != 2 {
		t.Fatalf("trusted root fetches = %d", fetches.Load())
	}
}

func TestSigstoreAttestationVerifierRejectsParsingAndPolicyFailures(t *testing.T) {
	t.Run("parse before trusted root fetch", func(t *testing.T) {
		var fetches atomic.Int32
		verifier := &sigstoreAttestationVerifier{fetchTrustedRoot: func() (root.TrustedMaterial, error) {
			fetches.Add(1)
			return nil, errors.New("must not fetch")
		}}
		err := verifier.Verify(context.Background(), []byte(`{"bad":true}`), attestationVerificationPolicy{})
		if err == nil || !strings.Contains(err.Error(), "parse Sigstore bundle") {
			t.Fatalf("Verify error = %v", err)
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
		verifier := &sigstoreAttestationVerifier{fetchTrustedRoot: func() (root.TrustedMaterial, error) {
			return trustedRoot, nil
		}}
		digestBytes, err := hex.DecodeString("bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b")
		if err != nil {
			t.Fatal(err)
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		err = verifier.Verify(context.Background(), bundleJSON, attestationVerificationPolicy{
			issuer: "http://oidc.local:8080", identity: "foo!oidc.local",
			predicate: attestationPredicate, assetName: "artifact", digest: digest,
		})
		if err == nil || !strings.Contains(err.Error(), "not an in-toto Statement v1") {
			t.Fatalf("Verify error = %v", err)
		}
	})
}
