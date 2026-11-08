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

package object

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casdoor/casdoor/auditsnapshot"
)

// sqliteSnapshotDSN opens a file database in WAL mode with a busy timeout, so
// a writer on a second connection does not fail while the read-snapshot
// transaction is open.
func sqliteSnapshotDSN(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	uri := "file:///" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	return uri
}

func newSnapshotTestOrmer(t *testing.T, dsn string) *Ormer {
	t.Helper()
	a, err := NewAdapter("sqlite", dsn, "")
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if err := a.Engine.Sync2(new(Record)); err != nil {
		t.Fatalf("Sync2(record): %v", err)
	}
	t.Cleanup(func() { _ = a.Engine.Close() })
	return a
}

func insertSeedRecord(t *testing.T, a *Ormer, id int64, org, action, createdTime string) {
	t.Helper()
	record := &Record{
		Id:           int(id),
		Owner:        org,
		Name:         "generated",
		CreatedTime:  createdTime,
		Organization: org,
		ClientIp:     "203.0.113.9",
		User:         "alice",
		Method:       "POST",
		RequestUri:   "/api/" + action,
		Action:       action,
		Language:     "zh",
		Object:       `{"note":"中文 — café 😀","big":9007199254740993}`,
		Response:     `{status:"ok"}`,
		StatusCode:   200,
		IsTriggered:  true,
	}
	affected, err := a.Engine.Insert(record)
	if err != nil {
		t.Fatalf("insert record id=%d: %v", id, err)
	}
	if affected != 1 {
		t.Fatalf("insert record id=%d affected=%d", id, affected)
	}
}

func independentVerifier(t *testing.T, signer auditsnapshot.Signer) *auditsnapshot.Verifier {
	t.Helper()
	// Simulate an out-of-band verifier deployment: persist only the public key,
	// reload it from disk, and build the anchor from that file.
	pubPEM, err := auditsnapshot.MarshalPublicKeyPEM(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "anchor.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := auditsnapshot.ParsePublicKeyPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := auditsnapshot.KeyIDOf(pub)
	if err != nil {
		t.Fatal(err)
	}
	v, err := auditsnapshot.NewVerifier(auditsnapshot.TrustedAnchor{KeyID: keyID, PublicKey: pub}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestAuditSnapshotFrozenSetDuringMutation freezes the actual ID set inside a
// fixed read snapshot and proves that rows inserted and deleted while the
// export is reading cannot change the selection or the pages.
func TestAuditSnapshotFrozenSetDuringMutation(t *testing.T) {
	dsn := sqliteSnapshotDSN(t)
	reader := newSnapshotTestOrmer(t, dsn)
	writer := newSnapshotTestOrmer(t, dsn)
	original := ormer
	ormer = reader
	t.Cleanup(func() { ormer = original })

	const created = "2026-11-01T00:00:00Z"
	// Interleave organizations so the selected IDs are non-contiguous: the
	// export cannot infer membership from a maximum auto-increment ID.
	orgAIDs := []int64{1, 3, 5, 7, 9, 10, 11, 12, 13, 14}
	orgBIDs := []int64{2, 4, 6, 8}
	orgBSet := map[int64]bool{}
	for _, id := range orgBIDs {
		orgBSet[id] = true
	}
	loginIDs := map[int64]bool{1: true, 3: true, 5: true, 7: true, 9: true}
	all := append(append([]int64{}, orgAIDs...), orgBIDs...)
	for _, id := range all {
		org, action := "org-a", "update"
		if orgBSet[id] {
			org, action = "org-b", "logout"
		}
		if loginIDs[id] {
			action = "login"
		}
		insertSeedRecord(t, reader, id, org, action, created)
	}

	priv, err := auditsnapshot.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := auditsnapshot.StaticSigner{Priv: priv}
	verifier := independentVerifier(t, signer)

	ctx := context.Background()
	tx, err := reader.Engine.DB().DB.BeginTx(ctx, snapshotTxOptions("sqlite"))
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })

	filter := auditsnapshot.SnapshotFilter{Organization: "org-a", MaxRecords: 100}
	ids, err := freezeAuditRecordIDs(ctx, tx, "sqlite", "record", filter)
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if len(ids) != len(orgAIDs) {
		t.Fatalf("frozen ids = %v, want %v", ids, orgAIDs)
	}
	for i, id := range orgAIDs {
		if ids[i] != id {
			t.Fatalf("frozen ids = %v, want %v", ids, orgAIDs)
		}
	}

	// Mutate the live table through a second connection while reading:
	// insert new org-a rows and delete frozen id 5 and org-b id 2.
	insertSeedRecord(t, writer, 15, "org-a", "login", created)
	insertSeedRecord(t, writer, 16, "org-a", "update", created)
	if _, err := writer.Engine.In("id", 5).Delete(&Record{}); err != nil {
		t.Fatalf("delete id 5: %v", err)
	}
	if _, err := writer.Engine.In("id", 2).Delete(&Record{}); err != nil {
		t.Fatalf("delete id 2: %v", err)
	}

	// Page strictly over the frozen set; the deleted row is still readable and
	// neither new row appears.
	var frozen []auditsnapshot.CanonicalRecord
	for start := 0; start < len(ids); start += 3 {
		end := start + 3
		if end > len(ids) {
			end = len(ids)
		}
		page, err := fetchAuditRecordsPage(ctx, tx, "record", ids[start:end])
		if err != nil {
			t.Fatalf("page %d: %v", start, err)
		}
		if len(page) != end-start {
			t.Fatalf("page %d returned %d rows, want %d", start, len(page), end-start)
		}
		for i, row := range page {
			if int64(row.Id) != ids[start+i] {
				t.Fatalf("page does not match frozen window: got id %d, want %d", row.Id, ids[start+i])
			}
			if row.Organization != "org-a" {
				t.Fatalf("foreign organization row leaked into snapshot: %s", row.Organization)
			}
			frozen = append(frozen, recordToCanonical(row))
		}
	}

	bundle, err := auditsnapshot.BuildBundle(filter, frozen, signer, time.Now(), "frozen-snap")
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	if err := verifier.VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	// Round-trip through the offline file format and verify again.
	raw, err := auditsnapshot.MarshalBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	offline, err := auditsnapshot.UnmarshalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyBundle(offline); err != nil {
		t.Fatalf("offline VerifyBundle: %v", err)
	}

	// A record deleted during the read remains provably included in the frozen
	// snapshot via a single-record inclusion proof.
	idx5 := -1
	for i, record := range offline.Records {
		if record.ID == 5 {
			idx5 = i
		}
	}
	if idx5 < 0 {
		t.Fatal("deleted record 5 missing from frozen snapshot")
	}
	proof5, err := offline.NewInclusionProof(idx5)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyInclusion(offline.Manifest, offline.Signature, offline.Records[idx5], proof5); err != nil {
		t.Fatalf("VerifyInclusion for deleted-but-frozen record: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A fresh export after the mutations sees the post-mutation table:
	// 5 and 2 are gone, 15 and 16 are present.
	bundle2, err := ExportAuditSnapshot(filter, signer)
	if err != nil {
		t.Fatalf("ExportAuditSnapshot: %v", err)
	}
	wantIDs := []int64{1, 3, 7, 9, 10, 11, 12, 13, 14, 15, 16}
	if len(bundle2.Manifest.RecordIDs) != len(wantIDs) {
		t.Fatalf("post-mutation ids = %v, want %v", bundle2.Manifest.RecordIDs, wantIDs)
	}
	for i, id := range wantIDs {
		if bundle2.Manifest.RecordIDs[i] != id {
			t.Fatalf("post-mutation ids = %v, want %v", bundle2.Manifest.RecordIDs, wantIDs)
		}
	}
	if err := verifier.VerifyBundle(bundle2); err != nil {
		t.Fatalf("VerifyBundle post-mutation: %v", err)
	}
}

// TestAuditSnapshotExportFiltersAndScope checks end-to-end export with action
// and time-window conditions, and proves an org-scoped export cannot carry
// another organization's rows.
func TestAuditSnapshotExportFiltersAndScope(t *testing.T) {
	dsn := sqliteSnapshotDSN(t)
	a := newSnapshotTestOrmer(t, dsn)
	original := ormer
	ormer = a
	t.Cleanup(func() { ormer = original })

	insertSeedRecord(t, a, 1, "org-a", "login", "2026-11-01T00:00:00Z")
	insertSeedRecord(t, a, 2, "org-b", "login", "2026-11-01T00:00:00Z")
	insertSeedRecord(t, a, 3, "org-a", "update", "2026-11-03T00:00:00Z")

	priv, _ := auditsnapshot.GeneratePrivateKey()
	signer := auditsnapshot.StaticSigner{Priv: priv}
	verifier := independentVerifier(t, signer)

	all, err := ExportAuditSnapshot(auditsnapshot.SnapshotFilter{Organization: "org-a", MaxRecords: 100}, signer)
	if err != nil {
		t.Fatalf("ExportAuditSnapshot: %v", err)
	}
	if err := verifier.VerifyBundle(all); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if len(all.Manifest.RecordIDs) != 2 || all.Manifest.RecordIDs[0] != 1 || all.Manifest.RecordIDs[1] != 3 {
		t.Fatalf("org-scoped ids = %v, want [1 3]", all.Manifest.RecordIDs)
	}

	logins, err := ExportAuditSnapshot(auditsnapshot.SnapshotFilter{Organization: "org-a", Action: "login", MaxRecords: 100}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(logins.Manifest.RecordIDs) != 1 || logins.Manifest.RecordIDs[0] != 1 {
		t.Fatalf("action-filtered ids = %v, want [1]", logins.Manifest.RecordIDs)
	}
	if logins.Manifest.FilterDigest == all.Manifest.FilterDigest {
		t.Fatal("filter digest does not distinguish the action condition")
	}
	if err := verifier.VerifyBundle(logins); err != nil {
		t.Fatalf("VerifyBundle logins: %v", err)
	}

	// From is inclusive, To is exclusive.
	window, err := ExportAuditSnapshot(auditsnapshot.SnapshotFilter{
		Organization: "org-a", CreatedTimeFrom: "2026-11-02T00:00:00Z", CreatedTimeTo: "2026-12-01T00:00:00Z", MaxRecords: 100,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(window.Manifest.RecordIDs) != 1 || window.Manifest.RecordIDs[0] != 3 {
		t.Fatalf("time-window ids = %v, want [3]", window.Manifest.RecordIDs)
	}

	after, err := ExportAuditSnapshot(auditsnapshot.SnapshotFilter{
		Organization: "org-a", CreatedTimeFrom: "2026-12-01T00:00:00Z", MaxRecords: 100,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Manifest.RecordIDs) != 0 {
		t.Fatalf("future-window ids = %v, want empty", after.Manifest.RecordIDs)
	}
	if err := verifier.VerifyBundle(after); err != nil {
		t.Fatalf("VerifyBundle empty window: %v", err)
	}

	// MaxRecords makes the selection finite.
	limited, err := ExportAuditSnapshot(auditsnapshot.SnapshotFilter{Organization: "org-a", MaxRecords: 1}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited.Manifest.RecordIDs) != 1 || limited.Manifest.RecordIDs[0] != 1 {
		t.Fatalf("limited ids = %v, want [1]", limited.Manifest.RecordIDs)
	}

	// A foreign record handed to BuildBundle can never enter an org-a export.
	foreign := all.Records[0]
	foreign.Organization = "org-b"
	if _, err := auditsnapshot.BuildBundle(auditsnapshot.SnapshotFilter{Organization: "org-a", MaxRecords: 100},
		[]auditsnapshot.CanonicalRecord{foreign}, signer, time.Now(), ""); err == nil {
		t.Fatal("cross-organization record was accepted into an org-a export")
	}
}

// TestRecordWriteAndCleanupCompatibility exercises the original Record insert
// (including write-time masking) and the retention cleanup path alongside the
// snapshot reader.
func TestRecordWriteAndCleanupCompatibility(t *testing.T) {
	dsn := sqliteSnapshotDSN(t)
	a := newSnapshotTestOrmer(t, dsn)
	original := ormer
	ormer = a
	t.Cleanup(func() { ormer = original })

	// AddRecord also tries webhooks/audit providers, whose tables do not exist
	// here; those lookups fail soft and the row is still inserted.
	record := &Record{
		Organization: "org-a",
		Method:       "POST",
		Action:       "login",
		CreatedTime:  "2026-11-01T00:00:00Z",
		Object:       `{"password":"plain-text-secret-777","user":"bob"}`,
	}
	if ok := AddRecord(record); !ok {
		t.Fatal("AddRecord returned false")
	}
	stored, err := GetRecords("org-a")
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored records = %d, want 1", len(stored))
	}
	if strings.Contains(stored[0].Object, "plain-text-secret-777") {
		t.Fatalf("write path persisted a raw secret: %s", stored[0].Object)
	}
	if !strings.Contains(stored[0].Object, `"password":"***"`) {
		t.Fatalf("write path did not mask the secret: %s", stored[0].Object)
	}
	if stored[0].Owner != "org-a" {
		t.Fatalf("owner = %s, want org-a", stored[0].Owner)
	}

	// A snapshot export reads the masked fact and never recovers plaintext.
	priv, _ := auditsnapshot.GeneratePrivateKey()
	signer := auditsnapshot.StaticSigner{Priv: priv}
	bundle, err := ExportAuditSnapshot(auditsnapshot.SnapshotFilter{Organization: "org-a", MaxRecords: 100}, signer)
	if err != nil {
		t.Fatalf("ExportAuditSnapshot: %v", err)
	}
	if err := independentVerifier(t, signer).VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	blob, _ := auditsnapshot.MarshalBundle(bundle)
	if strings.Contains(string(blob), "plain-text-secret-777") {
		t.Fatal("raw secret leaked into the snapshot bundle")
	}

	// The existing cleanup path deletes the row, and the next export is empty.
	deleted, err := cleanupOrgRecords("org-a", "2999-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("cleanupOrgRecords: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("cleanup deleted %d rows, want 1", deleted)
	}
	after, err := ExportAuditSnapshot(auditsnapshot.SnapshotFilter{Organization: "org-a", MaxRecords: 100}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if after.Manifest.RecordCount != 0 {
		t.Fatalf("records after cleanup = %d, want 0", after.Manifest.RecordCount)
	}
}

// TestExportAuditSnapshotRequiresSignerAndKey guards the no-default-key rule.
func TestExportAuditSnapshotRequiresSignerAndKey(t *testing.T) {
	dsn := sqliteSnapshotDSN(t)
	a := newSnapshotTestOrmer(t, dsn)
	original := ormer
	ormer = a
	t.Cleanup(func() { ormer = original })

	if _, err := ExportAuditSnapshot(auditsnapshot.SnapshotFilter{Organization: "org-a", MaxRecords: 100}, nil); err == nil {
		t.Fatal("export without a signer should fail")
	}
	t.Setenv("auditSnapshotSigningKeyFile", "")
	if _, err := NewConfiguredSnapshotSigner(); err == nil {
		t.Fatal("signer construction without configured key should fail")
	}
}
