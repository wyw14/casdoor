// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auditsnapshot

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func mustSigner(t *testing.T) StaticSigner {
	t.Helper()
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return StaticSigner{Priv: priv}
}

func verifierFor(t *testing.T, signer Signer) *Verifier {
	t.Helper()
	v, err := NewVerifier(TrustedAnchor{KeyID: signer.KeyID(), PublicKey: signer.PublicKey()}, 0)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func makeRecord(id int64, org, object string) CanonicalRecord {
	return CanonicalRecord{
		ID:           id,
		Owner:        org,
		Name:         "record-name",
		CreatedTime:  "2026-11-08T10:00:00Z",
		Organization: org,
		ClientIP:     "203.0.113.7",
		User:         "alice",
		Method:       "POST",
		RequestURI:   "/api/login",
		Action:       "login",
		Language:     "zh",
		Object:       object,
		Response:     `{status:"ok"}`,
		StatusCode:   200,
		Detail:       "",
		IsTriggered:  false,
	}
}

func buildFilter(org string, max int) SnapshotFilter {
	return SnapshotFilter{Organization: org, MaxRecords: max}
}

// TestMerkleProofVectors pins the deterministic tree shape: odd trailing
// nodes are promoted without duplication, and the proof length is exact for
// every index.
func TestMerkleProofVectors(t *testing.T) {
	cases := []struct {
		size, index, steps int
	}{
		{1, 0, 0},
		{2, 0, 1}, {2, 1, 1},
		{3, 0, 2}, {3, 1, 2}, {3, 2, 1},
		{4, 0, 2}, {4, 1, 2}, {4, 2, 2}, {4, 3, 2},
		{5, 0, 3}, {5, 4, 1},
		{8, 7, 3},
	}
	for _, c := range cases {
		got, err := expectedProofSteps(c.size, c.index)
		if err != nil {
			t.Fatalf("expectedProofSteps(%d,%d): %v", c.size, c.index, err)
		}
		if got != c.steps {
			t.Errorf("size=%d index=%d: want %d steps, got %d", c.size, c.index, c.steps, got)
		}
	}
	if got := treeDepth(5); got != 3 {
		t.Errorf("treeDepth(5) = %d, want 3", got)
	}
}

// TestMerkleInclusionAllSizes builds trees of every size 1..20 and verifies
// the folded proof of every leaf against the root.
func TestMerkleInclusionAllSizes(t *testing.T) {
	for size := 1; size <= 20; size++ {
		leaves := make([][]byte, size)
		for i := range leaves {
			r := makeRecord(int64(i+1), "org-a", "")
			d, err := r.Digest()
			if err != nil {
				t.Fatal(err)
			}
			leaves[i] = d
		}
		root := merkleRoot(leaves)

		for index := 0; index < size; index++ {
			steps, err := buildProof(leaves, index)
			if err != nil {
				t.Fatalf("size=%d index=%d: %v", size, index, err)
			}
			want, _ := expectedProofSteps(size, index)
			if len(steps) != want {
				t.Fatalf("size=%d index=%d: %d steps, want %d", size, index, len(steps), want)
			}
			got, err := foldProof(leaves[index], steps)
			if err != nil {
				t.Fatalf("size=%d index=%d: fold: %v", size, index, err)
			}
			if string(got) != string(root) {
				t.Fatalf("size=%d index=%d: root mismatch", size, index)
			}
		}
	}
}

// TestBuildVerifyUnicodeAndBigIntegers covers Unicode payloads, a 64-bit ID
// beyond the signed 32-bit range, and large integers embedded in the payload.
func TestBuildVerifyUnicodeAndBigIntegers(t *testing.T) {
	signer := mustSigner(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	records := []CanonicalRecord{
		makeRecord(2_100_000_001, "org-a", `{"note":"中文 — café 😀","big":9007199254740993}`),
		makeRecord(9_000_000_000_001, "org-a", `{"note":"日本語メモ 🎉"}`),
		makeRecord(42, "org-a", ""),
	}

	bundle, err := BuildBundle(buildFilter("org-a", 100), records, signer, now, "snap-fixed")
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	v := verifierFor(t, signer)
	if err := v.VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if bundle.Manifest.SnapshotID != "snap-fixed" || bundle.Manifest.CreatedAt != "2026-11-08T12:00:00Z" {
		t.Errorf("manifest identity not pinned: %+v", bundle.Manifest)
	}
	// IDs must be the actual frozen set in ascending order with the real count.
	wantIDs := []int64{42, 2100000001, 9000000000001}
	if len(bundle.Manifest.RecordIDs) != 3 {
		t.Fatalf("record ids = %v", bundle.Manifest.RecordIDs)
	}
	for i, id := range wantIDs {
		if bundle.Manifest.RecordIDs[i] != id {
			t.Errorf("record ids[%d] = %d, want %d", i, bundle.Manifest.RecordIDs[i], id)
		}
	}

	for i, record := range bundle.Records {
		proof, err := bundle.NewInclusionProof(i)
		if err != nil {
			t.Fatalf("NewInclusionProof(%d): %v", i, err)
		}
		if err := v.VerifyInclusion(bundle.Manifest, bundle.Signature, record, proof); err != nil {
			t.Fatalf("VerifyInclusion(%d): %v", i, err)
		}
	}
}

// TestEmptySnapshot verifies the finite-but-empty selection.
func TestEmptySnapshot(t *testing.T) {
	signer := mustSigner(t)
	bundle, err := BuildBundle(buildFilter("org-a", 10), nil, signer, time.Unix(0, 0).UTC(), "empty")
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	v := verifierFor(t, signer)
	if err := v.VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if bundle.Manifest.Merkle.LeafCount != 0 || len(bundle.Manifest.Merkle.RootHash) != 32 {
		t.Fatalf("bad empty tree summary: %+v", bundle.Manifest.Merkle)
	}
}

// TestMaskedFactNoSecretLeakage ensures secrets only exist post-mask in the
// exported fact, and never reach the bundle, the proof bytes or error text.
func TestMaskedFactNoSecretLeakage(t *testing.T) {
	signer := mustSigner(t)
	secret := `raw-password-t0psecret-9f3a`
	records := []CanonicalRecord{
		makeRecord(1, "org-a", `{"password":"`+secret+`","user":"bob"}`),
	}
	bundle, err := BuildBundle(buildFilter("org-a", 10), records, signer, time.Now(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bundle.Records[0].Object, `"password":"***"`) {
		t.Errorf("object not masked: %s", bundle.Records[0].Object)
	}
	proof, err := bundle.NewInclusionProof(0)
	if err != nil {
		t.Fatal(err)
	}

	bundleBytes, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, _ := json.Marshal(proof)
	for _, b := range [][]byte{bundleBytes, proofBytes} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("raw secret leaked into export artifact")
		}
	}

	// Re-applying the same revision must be idempotent.
	once := bundle.Records[0].Object
	twice := MaskSecrets(once)
	if once != twice {
		t.Fatalf("mask policy is not idempotent:\n%s\n%s", once, twice)
	}
	if bundle.Manifest.MaskPolicyRevision != MaskPolicyRevision {
		t.Fatalf("mask policy revision not committed: %s", bundle.Manifest.MaskPolicyRevision)
	}

	// Tamper with the record: errors name fields only and never echo payloads.
	tampered := bundle.Records[0]
	tampered.Object = `{"password":"` + secret + `","user":"eve"}`
	err = verifierFor(t, signer).VerifyInclusion(bundle.Manifest, bundle.Signature, tampered, proof)
	if !errors.Is(err, ErrRecordDigest) {
		t.Fatalf("want ErrRecordDigest, got %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error message leaks payload: %v", err)
	}
}

// TestTamperProofAndIndex covers a tampered sibling hash, an extra
// unconsumed node, a truncated proof and a tampered filter commitment.
func TestTamperProofAndIndex(t *testing.T) {
	signer := mustSigner(t)
	records := []CanonicalRecord{makeRecord(1, "org-a", "a"), makeRecord(2, "org-a", "b"), makeRecord(3, "org-a", "c")}
	bundle, err := BuildBundle(buildFilter("org-a", 10), records, signer, time.Now(), "s")
	if err != nil {
		t.Fatal(err)
	}
	v := verifierFor(t, signer)
	proof, err := bundle.NewInclusionProof(0)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper one index node (sibling hash).
	tamperedProof := *proof
	tamperedProof.Steps[0] = ProofStep{Side: "R", Hash: make([]byte, 32)}
	err = v.VerifyInclusion(bundle.Manifest, bundle.Signature, bundle.Records[0], &tamperedProof)
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("tampered index node: want ErrRootMismatch, got %v", err)
	}

	// Inject an extra, unconsumed node.
	extra := *proof
	extra.Steps = append(append([]ProofStep{}, proof.Steps...), ProofStep{Side: "R", Hash: make([]byte, 32)})
	err = v.VerifyInclusion(bundle.Manifest, bundle.Signature, bundle.Records[0], &extra)
	if !errors.Is(err, ErrUnexpectedNode) {
		t.Fatalf("extra node: want ErrUnexpectedNode, got %v", err)
	}

	// Truncate the proof.
	short := *proof
	short.Steps = proof.Steps[:len(proof.Steps)-1]
	err = v.VerifyInclusion(bundle.Manifest, bundle.Signature, bundle.Records[0], &short)
	if !errors.Is(err, ErrUnexpectedNode) {
		t.Fatalf("truncated proof: want ErrUnexpectedNode, got %v", err)
	}

	// Tamper the filter (and its committed digest): identity checks fail
	// before the signature is even examined.
	m2 := *bundle.Manifest
	m2.Filter.Action = "login"
	if err := v.VerifyManifest(&m2, bundle.Signature); !errors.Is(err, ErrFilterDigest) {
		t.Fatalf("tampered filter: want ErrFilterDigest, got %v", err)
	}

	// A forged recordCount/depth is rejected by the size/depth budget.
	m3 := *bundle.Manifest
	m3.Merkle.Depth = 99
	if err := v.VerifyManifest(&m3, bundle.Signature); !errors.Is(err, ErrSizeDepthBudget) {
		t.Fatalf("forged depth: want ErrSizeDepthBudget, got %v", err)
	}

	// Duplicate IDs are rejected.
	m4 := *bundle.Manifest
	m4.RecordIDs = append(append([]int64{}, m4.RecordIDs...), m4.RecordIDs[0])
	m4.RecordCount = len(m4.RecordIDs)
	if err := v.VerifyManifest(&m4, bundle.Signature); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("duplicate ids: want ErrDuplicateID, got %v", err)
	}
}

// TestWrongKeyAndWrongSnapshot checks signature failure with a different
// anchor, mismatched key id, and a proof bound to another snapshot.
func TestWrongKeyAndWrongSnapshot(t *testing.T) {
	signerA := mustSigner(t)
	signerB := mustSigner(t)
	records := []CanonicalRecord{makeRecord(1, "org-a", "a")}
	bundle, err := BuildBundle(buildFilter("org-a", 10), records, signerA, time.Now(), "snap-a")
	if err != nil {
		t.Fatal(err)
	}

	vB := verifierFor(t, signerB)
	if err := vB.VerifyBundle(bundle); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong anchor: want ErrSignature, got %v", err)
	}

	// Right key bytes but a verifier pinned to a different key identity.
	vWrongID, err := NewVerifier(TrustedAnchor{KeyID: "ed25519-deadbeef", PublicKey: signerA.PublicKey()}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := vWrongID.VerifyBundle(bundle); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key id: want ErrSignature, got %v", err)
	}

	proof, _ := bundle.NewInclusionProof(0)
	proof.SnapshotID = "snap-other"
	if err := verifierFor(t, signerA).VerifyInclusion(bundle.Manifest, bundle.Signature, bundle.Records[0], proof); !errors.Is(err, ErrWrongSnapshot) {
		t.Fatalf("wrong snapshot: want ErrWrongSnapshot, got %v", err)
	}
}

// TestCrossOrganizationRejection proves a record from another organization can
// neither enter the bundle nor pass an inclusion check.
func TestCrossOrganizationRejection(t *testing.T) {
	signer := mustSigner(t)
	records := []CanonicalRecord{
		makeRecord(1, "org-a", "a"),
		makeRecord(2, "org-b", "b"),
	}
	if _, err := BuildBundle(buildFilter("org-a", 10), records, signer, time.Now(), "s"); err == nil {
		t.Fatal("cross-organization record was accepted into an org-a export")
	}

	bundle, err := BuildBundle(buildFilter("org-a", 10), []CanonicalRecord{records[0]}, signer, time.Now(), "s")
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := bundle.NewInclusionProof(0)
	foreign := records[0]
	foreign.Organization = "org-b"
	err = verifierFor(t, signer).VerifyInclusion(bundle.Manifest, bundle.Signature, foreign, proof)
	if !errors.Is(err, ErrWrongOrganization) {
		t.Fatalf("foreign org record: want ErrWrongOrganization, got %v", err)
	}
}

// TestFilterDigestChanges proves the digest distinguishes different selections.
func TestFilterDigestChanges(t *testing.T) {
	f1 := buildFilter("org-a", 100)
	f2 := f1
	f2.MaxRecords = 50
	d1, _ := f1.Digest()
	d2, _ := f2.Digest()
	if d1 == d2 {
		t.Fatal("filter digest ignores the limit")
	}
	f3 := f1
	f3.Action = "login"
	d3, _ := f3.Digest()
	if d1 == d3 {
		t.Fatal("filter digest ignores the action condition")
	}
}

// TestFileSignerRoundTrip checks the dedicated PEM key provider and verifies
// against a public key parsed independently out of band.
func TestFileSignerRoundTrip(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot-key.pem")
	if err := WriteKeyFile(path, priv); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("key file permission = %v, want 0600", info.Mode().Perm())
		}
	}

	loaded, err := NewFileSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KeyID() != (StaticSigner{Priv: priv}).KeyID() {
		t.Fatal("key id mismatch")
	}

	// The verifier obtains its anchor from a public key file alone.
	pubPEM, err := MarshalPublicKeyPEM(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "snapshot-pub.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKeyPEM(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := KeyIDOf(pub)
	v, err := NewVerifier(TrustedAnchor{KeyID: keyID, PublicKey: pub}, 0)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := BuildBundle(buildFilter("org-a", 10), []CanonicalRecord{makeRecord(7, "org-a", "x")}, loaded, time.Now(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyBundle(bundle); err != nil {
		t.Fatalf("verification with out-of-band anchor failed: %v", err)
	}
}

// TestMissingSignerAndLimits covers producer-side validation.
func TestMissingSignerAndLimits(t *testing.T) {
	if _, err := BuildBundle(buildFilter("org-a", 10), nil, nil, time.Now(), "s"); err == nil {
		t.Fatal("expected error for missing signer")
	}
	if _, err := BuildBundle(SnapshotFilter{Organization: "org-a", MaxRecords: MaxRecordsHardLimit + 1}, nil, mustSigner(t), time.Now(), "s"); err == nil {
		t.Fatal("expected error for oversized limit")
	}
	if _, err := BuildBundle(buildFilter("", 10), nil, mustSigner(t), time.Now(), "s"); err == nil {
		t.Fatal("expected error for empty organization")
	}
}
