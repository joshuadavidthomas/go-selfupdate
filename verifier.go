package selfupdate

import "context"

// AttestationRequest describes one attestation to verify: the exact signer
// identity and artifact binding Check derived from the release. All fields
// are inputs the verifier must enforce; none are advisory.
type AttestationRequest struct {
	SignerIdentity   string // https://github.com/<owner>/<repo>/<workflow>@refs/tags/<version>
	Issuer           string // OIDC issuer, e.g. https://token.actions.githubusercontent.com
	PredicateType    string // https://slsa.dev/provenance/v1
	AssetName        string // exact release asset filename
	DigestSHA256     [32]byte
	SourceRepository string // https://github.com/<owner>/<repo>
	SourceOwner      string // https://github.com/<owner>
}

// AttestationVerifier verifies one attestation bundle against a request,
// returning nil only when every field of the request is satisfied.
type AttestationVerifier interface {
	VerifyAttestation(ctx context.Context, bundleJSON []byte, request AttestationRequest) error
}
