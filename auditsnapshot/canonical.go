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
	"crypto/sha256"
	"encoding/json"
)

const (
	// FormatVersion identifies the snapshot envelope, manifest and Merkle rules.
	FormatVersion = "casdoor-audit-snapshot-v1"
	// RecordFormatVersion identifies the canonical per-record encoding below.
	RecordFormatVersion = "casdoor-audit-record-v1"
	// FilterFormatVersion identifies the canonical encoding of selection conditions.
	FilterFormatVersion = "casdoor-audit-filter-v1"

	// HashAlgorithm is the only digest algorithm used by this revision.
	HashAlgorithm = "SHA-256"
	// SignatureAlgorithm is the only signature algorithm used by this revision.
	SignatureAlgorithm = "Ed25519"

	// MaxRecordsHardLimit bounds how many records one snapshot may commit, so a
	// crafted manifest cannot make a verifier allocate unbounded memory.
	MaxRecordsHardLimit = 1_000_000
)

// CanonicalRecord is the versioned, field-ordered projection of an audit row.
// The JSON field order below is part of the signed format: do not reorder or
// insert fields without introducing a new RecordFormatVersion.
type CanonicalRecord struct {
	ID           int64  `json:"id"`
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	CreatedTime  string `json:"createdTime"`
	Organization string `json:"organization"`
	ClientIP     string `json:"clientIp"`
	User         string `json:"user"`
	Method       string `json:"method"`
	RequestURI   string `json:"requestUri"`
	Action       string `json:"action"`
	Language     string `json:"language"`
	Object       string `json:"object"`
	Response     string `json:"response"`
	StatusCode   int    `json:"statusCode"`
	Detail       string `json:"detail"`
	IsTriggered  bool   `json:"isTriggered"`
}

// canonicalJSON serializes a value with a fixed struct-field order and without
// the default HTML escaping, so any conforming implementation can reproduce the
// exact bytes. Only ordered structs (never Go maps) are passed in.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func domainSeparatedSum(domain string, payload []byte) []byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(payload)
	return h.Sum(nil)
}

// Digest returns the record digest: SHA-256 over the revision tag and the
// canonical encoding. Exporters call this only after MaskSecrets has been
// applied at MaskPolicyRevision.
func (r CanonicalRecord) Digest() ([]byte, error) {
	b, err := canonicalJSON(r)
	if err != nil {
		return nil, err
	}
	return domainSeparatedSum(RecordFormatVersion, b), nil
}
