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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SnapshotBundle is the portable export: the signed manifest, the masked
// canonical records in the frozen order, and the signature block.
type SnapshotBundle struct {
	Manifest  *Manifest         `json:"manifest"`
	Records   []CanonicalRecord `json:"records"`
	Signature SignatureBlock    `json:"signature"`
}

// NewInclusionProof builds the single-record inclusion proof for the record at
// leafIndex. The records must be ordered exactly as Manifest.RecordIDs.
func (b *SnapshotBundle) NewInclusionProof(leafIndex int) (*InclusionProof, error) {
	if b == nil || b.Manifest == nil {
		return nil, errors.New("snapshot: missing manifest")
	}
	if leafIndex < 0 || leafIndex >= len(b.Records) {
		return nil, errors.New("snapshot: leaf index out of range")
	}

	leaves := make([][]byte, len(b.Records))
	for i, record := range b.Records {
		digest, err := record.Digest()
		if err != nil {
			return nil, err
		}
		leaves[i] = digest
	}

	steps, err := buildProof(leaves, leafIndex)
	if err != nil {
		return nil, err
	}
	record := b.Records[leafIndex]
	return &InclusionProof{
		FormatVersion: FormatVersion,
		SnapshotID:    b.Manifest.SnapshotID,
		Organization:  b.Manifest.Organization,
		RecordID:      record.ID,
		LeafIndex:     leafIndex,
		RecordDigest:  leaves[leafIndex],
		Steps:         steps,
	}, nil
}

// MarshalBundle serializes a bundle as JSON.
func MarshalBundle(b *SnapshotBundle) ([]byte, error) {
	return json.Marshal(b)
}

// UnmarshalBundle parses a bundle. Parsing alone establishes no trust: call
// Verifier.VerifyBundle before using the contents.
func UnmarshalBundle(data []byte) (*SnapshotBundle, error) {
	var b SnapshotBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("snapshot: failed to parse bundle: %w", err)
	}
	return &b, nil
}

func newSnapshotID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// BuildBundle produces a signed snapshot from the already-frozen record set.
// The producer must have materialized the finite ID set inside a fixed read
// snapshot before calling this; this function never queries a database and
// never re-selects "latest" rows.
//
// Every record is re-masked at MaskPolicyRevision before its digest is taken;
// the masked payload is the exported fact. Records from another organization,
// duplicate IDs and non-positive IDs are rejected.
func BuildBundle(filter SnapshotFilter, records []CanonicalRecord, signer Signer, now time.Time, snapshotID string) (*SnapshotBundle, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("snapshot: signer is required")
	}
	if len(records) > filter.MaxRecords {
		return nil, errors.New("snapshot: selected records exceed the filter limit")
	}

	seenIDs := make(map[int64]struct{}, len(records))
	masked := make([]CanonicalRecord, len(records))
	for i, record := range records {
		if record.Organization != filter.Organization {
			return nil, fmt.Errorf("snapshot: record %d belongs to another organization", record.ID)
		}
		if record.ID <= 0 {
			return nil, errors.New("snapshot: record id must be positive")
		}
		if _, exists := seenIDs[record.ID]; exists {
			return nil, fmt.Errorf("snapshot: duplicate record id %d", record.ID)
		}
		seenIDs[record.ID] = struct{}{}

		record.Object = MaskSecrets(record.Object)
		masked[i] = record
	}

	sort.Slice(masked, func(i, j int) bool { return masked[i].ID < masked[j].ID })

	ids := make([]int64, len(masked))
	leaves := make([][]byte, len(masked))
	for i, record := range masked {
		ids[i] = record.ID
		digest, err := record.Digest()
		if err != nil {
			return nil, err
		}
		leaves[i] = digest
	}

	filterDigest, err := filter.Digest()
	if err != nil {
		return nil, err
	}
	if snapshotID == "" {
		snapshotID, err = newSnapshotID()
		if err != nil {
			return nil, err
		}
	}
	if now.IsZero() {
		now = time.Now()
	}

	manifest := &Manifest{
		FormatVersion:      FormatVersion,
		SnapshotID:         snapshotID,
		CreatedAt:          now.UTC().Format(time.RFC3339),
		Organization:       filter.Organization,
		Filter:             filter,
		FilterDigest:       filterDigest,
		MaskPolicyRevision: MaskPolicyRevision,
		RecordIDs:          ids,
		RecordCount:        len(ids),
		Merkle: MerkleSummary{
			Algorithm: HashAlgorithm,
			LeafCount: len(ids),
			Depth:     treeDepth(len(ids)),
			RootHash:  merkleRoot(leaves),
		},
	}

	signingBytes, err := SigningBytes(manifest)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(signingBytes)
	if err != nil {
		return nil, fmt.Errorf("snapshot: failed to sign manifest: %w", err)
	}

	return &SnapshotBundle{
		Manifest: manifest,
		Records:  masked,
		Signature: SignatureBlock{
			Algorithm: SignatureAlgorithm,
			KeyID:     signer.KeyID(),
			Signature: signature,
		},
	}, nil
}
