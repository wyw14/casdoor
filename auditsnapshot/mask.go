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

// Package auditsnapshot exports a finite, organization-scoped set of audit
// records into canonically encoded, Merkle-indexed and independently signed
// snapshots, and verifies such snapshots fully offline. The verifier needs only
// the snapshot bytes and a public key anchor that the caller supplies
// explicitly; it never reads the producer database.
//
// A snapshot proves only that the listed records are included in the frozen
// selection described by its filter. It never proves that events the system
// did not record are absent, and hashes stored next to the source data do not
// protect against a database administrator: trust comes from the signature
// checked against an external anchor.
package auditsnapshot

import (
	"regexp"
	"strings"
)

// MaskPolicyRevision pins the exact masking rules that an export applies to a
// record's "object" payload before its digest is computed. The stored rows are
// already masked at write time, so the same revision is re-applied
// idempotently; masked payloads are exported as fact and the original
// plaintext is never reconstructed or guessed.
//
// Bump this revision whenever SecretRecordKeys or SecretRecordKeyPatterns
// change, so that producers and verifiers can never disagree on the policy.
const MaskPolicyRevision = "casdoor-record-secrets-v1"

var SecretRecordKeys = []string{
	"password", "oldPassword", "newPassword", "masterPassword", "defaultPassword", "passwordSalt", "passwordObfuscatorKey",
	"clientSecret", "client_secret", "clientSecret2", "accessSecret", "secret", "secretKey", "privateKey", "sslKey", "kerberosKeytab",
	"token", "accessToken", "access_token", "refreshToken", "refresh_token", "idToken", "id_token", "registrationAccessToken",
	"originalToken", "originalRefreshToken", "totpSecret", "masterVerificationCode",
	"code_verifier", "passcode", "recoveryCode", "recoveryCodes",
}

// SecretRecordKeyPatterns match the per-provider OAuth tokens kept in a user's properties
var SecretRecordKeyPatterns = []string{`oauth_[^"&=]*_(?:accessToken|refreshToken)`}

var (
	secretJsonRegex      *regexp.Regexp
	secretFormRegex      *regexp.Regexp
	secretMultipartRegex *regexp.Regexp
)

func init() {
	keys := strings.Join(append(append([]string{}, SecretRecordKeys...), SecretRecordKeyPatterns...), "|")
	jsonString := `"(?:[^"\\]|\\.)*"`
	secretJsonRegex = regexp.MustCompile(`(?i)"(` + keys + `)"\s*:\s*(?:` + jsonString + `|\[(?:` + jsonString + `|[^\]"])*\])`)
	secretFormRegex = regexp.MustCompile(`(?i)(^|&)(` + keys + `)=[^&]*`)
	secretMultipartRegex = regexp.MustCompile(`(?i)(name="(?:` + keys + `)"\r?\n\r?\n)[^\r\n]*`)
}

// MaskSecrets replaces known secret fields in JSON, form-urlencoded and
// multipart payloads with a fixed marker.
func MaskSecrets(recordString string) string {
	recordString = secretJsonRegex.ReplaceAllString(recordString, `"$1":"***"`)
	recordString = secretFormRegex.ReplaceAllString(recordString, "${1}${2}=***")
	return secretMultipartRegex.ReplaceAllString(recordString, "${1}***")
}
