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
	"errors"
	"fmt"
)

// Leaf and node hashes are domain-separated so that a second-preimage cannot
// be presented as the other kind.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// ProofStep is one sibling on the path from a leaf to the root. Side is the
// position of the sibling: "L" means the sibling is the left child and the
// running hash is the right child; "R" means the opposite.
type ProofStep struct {
	Side string `json:"side"`
	Hash []byte `json:"hash"`
}

// InclusionProof is a self-contained single-record inclusion proof. It carries
// hashes and identifiers only; it never contains record payloads or secrets.
type InclusionProof struct {
	FormatVersion string      `json:"formatVersion"`
	SnapshotID    string      `json:"snapshotId"`
	Organization  string      `json:"organization"`
	RecordID      int64       `json:"recordId"`
	LeafIndex     int         `json:"leafIndex"`
	RecordDigest  []byte      `json:"recordDigest"`
	Steps         []ProofStep `json:"steps"`
}

func hashLeaf(recordDigest []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(recordDigest)
	return h.Sum(nil)
}

func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// treeDepth returns the number of levels above the leaves: 0 for an empty or
// single-leaf tree, ceil(log2(n)) otherwise.
func treeDepth(n int) int {
	if n <= 1 {
		return 0
	}
	depth := 0
	for width := n; width > 1; width = (width + 1) / 2 {
		depth++
	}
	return depth
}

// merkleRoot folds the record digests left to right, applying the leaf prefix
// first. When a level has an odd width the trailing node is promoted unchanged
// (no duplicate hashing), which makes the tree and all proofs deterministic.
func merkleRoot(recordDigests [][]byte) []byte {
	if len(recordDigests) == 0 {
		return emptyTreeRoot
	}
	level := make([][]byte, len(recordDigests))
	for i, d := range recordDigests {
		level[i] = hashLeaf(d)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
			} else {
				next = append(next, hashNode(level[i], level[i+1]))
			}
		}
		level = next
	}
	return level[0]
}

// expectedProofSteps returns the exact number of siblings a proof for index in
// a tree of the given size must contain. Promotions of an odd trailing node do
// not add a step.
func expectedProofSteps(size, index int) (int, error) {
	if size <= 0 {
		return 0, errors.New("merkle: empty tree has no proof")
	}
	if index < 0 || index >= size {
		return 0, errors.New("merkle: leaf index out of range")
	}
	steps := 0
	width, i := size, index
	for width > 1 {
		if i%2 == 0 && i+1 < width {
			steps++
		} else if i%2 == 1 {
			steps++
		}
		i /= 2
		width = (width + 1) / 2
	}
	return steps, nil
}

// buildProof collects the sibling hashes for index in a tree built over the
// given record digests.
func buildProof(recordDigests [][]byte, index int) ([]ProofStep, error) {
	if index < 0 || index >= len(recordDigests) {
		return nil, errors.New("merkle: leaf index out of range")
	}
	steps := []ProofStep{}
	level := make([][]byte, len(recordDigests))
	for i, d := range recordDigests {
		level[i] = hashLeaf(d)
	}
	i := index
	for len(level) > 1 {
		if i%2 == 1 {
			steps = append(steps, ProofStep{Side: "L", Hash: level[i-1]})
		} else if i+1 < len(level) {
			steps = append(steps, ProofStep{Side: "R", Hash: level[i+1]})
		}
		i /= 2
		next := make([][]byte, 0, (len(level)+1)/2)
		for j := 0; j < len(level); j += 2 {
			if j+1 == len(level) {
				next = append(next, level[j])
			} else {
				next = append(next, hashNode(level[j], level[j+1]))
			}
		}
		level = next
	}
	return steps, nil
}

// foldProof recomputes the root from a leaf digest and the proof steps.
func foldProof(recordDigest []byte, steps []ProofStep) ([]byte, error) {
	h := hashLeaf(recordDigest)
	for i, step := range steps {
		switch step.Side {
		case "L":
			h = hashNode(step.Hash, h)
		case "R":
			h = hashNode(h, step.Hash)
		default:
			return nil, fmt.Errorf("merkle: invalid proof step side at index %d", i)
		}
		if len(step.Hash) != sha256.Size {
			return nil, fmt.Errorf("merkle: invalid proof step hash length at index %d", i)
		}
	}
	return h, nil
}
