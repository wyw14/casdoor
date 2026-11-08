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
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
)

var (
	ErrFormatVersion     = errors.New("verifier: unsupported format version")
	ErrManifestIdentity  = errors.New("verifier: invalid manifest identity")
	ErrFilterDigest      = errors.New("verifier: filter digest mismatch")
	ErrMaskPolicy        = errors.New("verifier: unknown mask policy revision")
	ErrDuplicateID       = errors.New("verifier: duplicate record id in snapshot")
	ErrSizeDepthBudget   = errors.New("verifier: size/depth budget violated")
	ErrSignature         = errors.New("verifier: manifest signature is invalid")
	ErrWrongOrganization = errors.New("verifier: record belongs to another organization")
	ErrWrongSnapshot     = errors.New("verifier: proof is bound to another snapshot")
	ErrRecordDigest      = errors.New("verifier: record digest mismatch")
	ErrUnexpectedNode    = errors.New("verifier: unexpected proof node")
	ErrRootMismatch      = errors.New("verifier: merkle root mismatch")
	ErrBundleRecords     = errors.New("verifier: bundle records do not match the manifest")
)

// TrustedAnchor is the verifier's explicit trust input: a key identity and its
// public key, provisioned out of band. Nothing embedded in a snapshot can
// replace it.
type TrustedAnchor struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

// Verifier checks snapshots offline. Zero value is not usable; construct it
// with NewVerifier.
type Verifier struct {
	anchor     TrustedAnchor
	maxRecords int
}

// NewVerifier creates a verifier pinned to one trusted anchor. maxRecords is
// the verifier-local resource budget; non-positive values fall back to
// MaxRecordsHardLimit.
func NewVerifier(anchor TrustedAnchor, maxRecords int) (*Verifier, error) {
	if anchor.KeyID == "" {
		return nil, errors.New("verifier: anchor key id is empty")
	}
	if len(anchor.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("verifier: anchor public key is not Ed25519")
	}
	if maxRecords <= 0 {
		maxRecords = MaxRecordsHardLimit
	}
	return &Verifier{anchor: anchor, maxRecords: maxRecords}, nil
}

// validateManifestIdentity checks format, self-consistency, filter
// commitment and the size/depth budget. It deliberately runs before any
// signature or proof work. Error messages name fields only, never payloads.
func validateManifestIdentity(m *Manifest, maxRecords int) error {
	if m == nil {
		return ErrManifestIdentity
	}
	if m.FormatVersion != FormatVersion {
		return ErrFormatVersion
	}
	if m.SnapshotID == "" || m.Organization == "" {
		return ErrManifestIdentity
	}
	if m.MaskPolicyRevision != MaskPolicyRevision {
		return ErrMaskPolicy
	}
	if err := m.Filter.Validate(); err != nil {
		return err
	}
	if m.Filter.Organization != m.Organization {
		return ErrManifestIdentity
	}
	expectedFilterDigest, err := m.Filter.Digest()
	if err != nil {
		return err
	}
	if m.FilterDigest != expectedFilterDigest {
		return ErrFilterDigest
	}

	if m.RecordCount < 0 || m.RecordCount > maxRecords {
		return ErrSizeDepthBudget
	}
	if len(m.RecordIDs) != m.RecordCount {
		return ErrSizeDepthBudget
	}
	ids := make(map[int64]struct{}, m.RecordCount)
	for _, id := range m.RecordIDs {
		if id <= 0 {
			return ErrManifestIdentity
		}
		if _, exists := ids[id]; exists {
			return ErrDuplicateID
		}
		ids[id] = struct{}{}
	}

	if m.Merkle.Algorithm != HashAlgorithm {
		return ErrSizeDepthBudget
	}
	if m.Merkle.LeafCount != m.RecordCount || m.Merkle.Depth != treeDepth(m.RecordCount) {
		return ErrSizeDepthBudget
	}
	if len(m.Merkle.RootHash) != sha256.Size {
		return ErrSizeDepthBudget
	}
	return nil
}

// VerifyManifest validates the manifest identity and verifies its signature
// against the explicit anchor.
func (v *Verifier) VerifyManifest(m *Manifest, sig SignatureBlock) error {
	if err := validateManifestIdentity(m, v.maxRecords); err != nil {
		return err
	}
	if sig.Algorithm != SignatureAlgorithm {
		return ErrSignature
	}
	// A snapshot cannot rotate its own trust anchor: the key identity must be
	// the one the verifier was configured with.
	if sig.KeyID != v.anchor.KeyID {
		return ErrSignature
	}
	signingBytes, err := SigningBytes(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(v.anchor.PublicKey, signingBytes, sig.Signature) {
		return ErrSignature
	}
	return nil
}

// VerifyBundle fully re-derives the Merkle index from the exported records and
// compares it to the signed manifest.
func (v *Verifier) VerifyBundle(b *SnapshotBundle) error {
	if b == nil {
		return ErrBundleRecords
	}
	if err := v.VerifyManifest(b.Manifest, b.Signature); err != nil {
		return err
	}
	if len(b.Records) != b.Manifest.RecordCount {
		return ErrBundleRecords
	}

	leaves := make([][]byte, len(b.Records))
	for i, record := range b.Records {
		if record.Organization != b.Manifest.Organization {
			return ErrWrongOrganization
		}
		if record.ID != b.Manifest.RecordIDs[i] {
			return ErrBundleRecords
		}
		digest, err := record.Digest()
		if err != nil {
			return err
		}
		leaves[i] = digest
	}
	if !bytes.Equal(merkleRoot(leaves), b.Manifest.Merkle.RootHash) {
		return ErrRootMismatch
	}
	return nil
}

// VerifyInclusion verifies that one record is included in the snapshot. It
// re-runs the full manifest checks, so a caller cannot skip signature or
// budget verification. A nil error proves inclusion of record in the frozen
// selection only; it never proves that other events were not recorded by the
// system.
func (v *Verifier) VerifyInclusion(m *Manifest, sig SignatureBlock, record CanonicalRecord, proof *InclusionProof) error {
	if err := v.VerifyManifest(m, sig); err != nil {
		return err
	}
	if proof == nil {
		return ErrUnexpectedNode
	}
	if proof.FormatVersion != FormatVersion ||
		proof.SnapshotID != m.SnapshotID ||
		proof.Organization != m.Organization ||
		proof.RecordID != record.ID {
		return ErrWrongSnapshot
	}
	if record.Organization != m.Organization {
		return ErrWrongOrganization
	}
	if proof.LeafIndex < 0 || proof.LeafIndex >= m.RecordCount || m.RecordIDs[proof.LeafIndex] != record.ID {
		return ErrWrongSnapshot
	}

	digest, err := record.Digest()
	if err != nil {
		return err
	}
	if !bytes.Equal(proof.RecordDigest, digest) {
		return ErrRecordDigest
	}

	expectedSteps, err := expectedProofSteps(m.RecordCount, proof.LeafIndex)
	if err != nil {
		return ErrUnexpectedNode
	}
	// Reject both truncated proofs and extra, unconsumed nodes.
	if len(proof.Steps) != expectedSteps {
		return ErrUnexpectedNode
	}
	if expectedSteps > m.Merkle.Depth {
		return ErrSizeDepthBudget
	}

	root, err := foldProof(digest, proof.Steps)
	if err != nil {
		return ErrUnexpectedNode
	}
	if !bytes.Equal(root, m.Merkle.RootHash) {
		return ErrRootMismatch
	}
	return nil
}
