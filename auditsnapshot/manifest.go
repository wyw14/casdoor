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
	"crypto/sha256"
)

// emptyTreeRoot is the distinguished root of a zero-leaf tree, so an empty
// selection is never confused with a missing hash.
var emptyTreeRoot = func() []byte {
	h := sha256.New()
	h.Write([]byte(FormatVersion))
	h.Write([]byte{0})
	h.Write([]byte("empty-tree"))
	return h.Sum(nil)
}()

// MerkleSummary commits the deterministic index. LeafCount and Depth are
// redundant with the record list, which lets the verifier detect tampering and
// enforce its size/depth budget before touching any proof.
type MerkleSummary struct {
	Algorithm string `json:"algorithm"`
	LeafCount int    `json:"leafCount"`
	Depth     int    `json:"depth"`
	RootHash  []byte `json:"rootHash"`
}

// Manifest is the signed identity of one snapshot. RecordIDs is the complete
// set that was actually selected and frozen in the read transaction, together
// with its count: a snapshot never infers membership from a maximum
// auto-increment ID or assumes that smaller IDs all exist.
type Manifest struct {
	FormatVersion      string         `json:"formatVersion"`
	SnapshotID         string         `json:"snapshotId"`
	CreatedAt          string         `json:"createdAt"`
	Organization       string         `json:"organization"`
	Filter             SnapshotFilter `json:"filter"`
	FilterDigest       string         `json:"filterDigest"`
	MaskPolicyRevision string         `json:"maskPolicyRevision"`
	RecordIDs          []int64        `json:"recordIds"`
	RecordCount        int            `json:"recordCount"`
	Merkle             MerkleSummary  `json:"merkle"`
}

// SignatureBlock binds the signature to an explicit key identity. The matching
// public key is never trusted because it appears here: the verifier supplies
// the trusted anchor separately.
type SignatureBlock struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Signature []byte `json:"signature"`
}

// SigningBytes is the exact byte sequence the signer signs and the verifier
// reconstructs.
func SigningBytes(m *Manifest) ([]byte, error) {
	b, err := canonicalJSON(m)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(FormatVersion), 0), b...), nil
}
