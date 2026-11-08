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

package scim

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/elimity-com/scim"
	"github.com/scim2/filter-parser/v2"
)

func parseTestFilter(t *testing.T, raw string) filter.Expression {
	t.Helper()
	expr, err := filter.ParseFilter([]byte(raw))
	if err != nil {
		t.Fatalf("parse filter %q: %v", raw, err)
	}
	return expr
}

func TestCanonicalFilterStable(t *testing.T) {
	variants := []string{
		`userName eq "alice"`,
		`USERNAME eq "alice"`,
		`username eq "alice"`,
		`UserName Eq "alice"`,
	}
	first := ""
	for i, raw := range variants {
		canon := canonicalFilter(parseTestFilter(t, raw))
		if i == 0 {
			first = canon
			continue
		}
		if canon != first {
			t.Fatalf("canonical filter drifted: %q vs %q", canon, first)
		}
	}

	compoundA := canonicalFilter(parseTestFilter(t, `displayName co "a" and userName sw "u"`))
	compoundB := canonicalFilter(parseTestFilter(t, `DISPLAYNAME co "a" AND USERNAME sw "u"`))
	if compoundA != compoundB {
		t.Fatalf("compound canonicalization drifted: %q vs %q", compoundA, compoundB)
	}

	notCanon := canonicalFilter(parseTestFilter(t, `not (emails pr)`))
	if notCanon != `not(emails pr)` {
		t.Fatalf("not filter canonicalized to %q", notCanon)
	}
}

func TestCanonicalAttrList(t *testing.T) {
	got := canonicalAttrList("userName, emails ,userName,displayName")
	want := []string{"displayname", "emails", "username", "username"}
	if len(got) != 3 {
		t.Fatalf("dedup failed: %v", got)
	}
	for i := range want[:3] {
		if got[i] != want[i] {
			t.Fatalf("sorted canonical attrs = %v, want %v", got, want[:3])
		}
	}
	if canonicalAttrList("  ") != nil {
		t.Fatal("blank attribute list should be nil")
	}
}

func TestProjectAttributes(t *testing.T) {
	attrs := scim.ResourceAttributes{
		"userName":    "alice",
		"displayName": "Alice",
		"name": scim.ResourceAttributes{
			"givenName":  "A",
			"familyName": "B",
			"formatted":  "A B",
		},
		"emails": []scim.ResourceAttributes{{"value": "a@example.test", "primary": false}},
		UserExtensionKey: scim.ResourceAttributes{
			"organization": "org1",
		},
	}

	includeOnly := projectAttributes(attrs, []attrRequest{{name: "username"}}, nil)
	if len(includeOnly) != 1 || includeOnly["userName"] != "alice" {
		t.Fatalf("whitelist projection wrong: %#v", includeOnly)
	}

	subInclude := projectAttributes(attrs, []attrRequest{{name: "emails", sub: "value"}}, nil)
	emails := attrMaps(subInclude["emails"])
	if len(emails) != 1 || len(emails[0]) != 1 || emails[0]["value"] != "a@example.test" {
		t.Fatalf("sub-attribute whitelist wrong: %#v", subInclude["emails"])
	}

	nameSub := projectAttributes(attrs, []attrRequest{{name: "name", sub: "familyname"}}, nil)
	nameMap, _ := asAttributeMap(nameSub["name"])
	if len(nameMap) != 1 || nameMap["familyName"] != "B" {
		t.Fatalf("complex sub-attribute whitelist wrong: %#v", nameSub["name"])
	}

	exclude := projectAttributes(attrs, nil, []attrRequest{{name: "emails"}})
	if _, ok := exclude["emails"]; ok {
		t.Fatal("excluded emails survived")
	}
	if exclude["userName"] != "alice" {
		t.Fatal("exclude removed an unrelated attribute")
	}

	extensionInclude := projectAttributes(attrs, []attrRequest{
		parseAttrRequest(UserExtensionKey),
		parseAttrRequest(UserExtensionKey + ".organization"),
	}, nil)
	extension, ok := extensionInclude[UserExtensionKey].(scim.ResourceAttributes)
	if !ok || len(extension) != 1 || extension["organization"] != "org1" {
		t.Fatalf("extension projection wrong: %#v", extensionInclude)
	}

	if got := projectAttributes(attrs, nil, nil); len(got) != len(attrs) {
		t.Fatal("empty projection must return the original attributes untouched")
	}
}

func TestPageFromFrozen(t *testing.T) {
	resources := []scim.Resource{{ID: "1"}, {ID: "2"}, {ID: "3"}, {ID: "4"}}

	page := pageFromFrozen(resources, 4, 1, 2)
	if got := resourceIDs(page.Resources); len(got) != 2 || got[0] != "1" || got[1] != "2" || page.TotalResults != 4 {
		t.Fatalf("first page wrong: %#v", page)
	}

	page = pageFromFrozen(resources, 4, 3, 2)
	if got := resourceIDs(page.Resources); len(got) != 2 || got[0] != "3" || got[1] != "4" {
		t.Fatalf("second page wrong: %#v", page)
	}

	page = pageFromFrozen(resources, 4, 100, 2)
	if len(page.Resources) != 0 || page.TotalResults != 4 {
		t.Fatalf("out of range page wrong: %#v", page)
	}

	page = pageFromFrozen(resources, 4, 1, 0)
	if page.Resources != nil || page.TotalResults != 4 {
		t.Fatalf("count=0 must keep TotalResults fixed without resources: %#v", page)
	}
}

func TestSealOpenRoundTripAndTamper(t *testing.T) {
	manager := newTestManager(t, snapshotConfig{})
	plaintext := []byte(`{"schemaVersion":"casdoor-scim-snapshot-v1","totalResults":1}`)

	sealed, err := manager.seal(plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := manager.openSealed(sealed)
	if err != nil {
		t.Fatalf("openSealed: %v", err)
	}
	if opened.TotalResults != 1 || opened.SchemaVersion != SnapshotSchemaVersion {
		t.Fatalf("round trip payload wrong: %#v", opened)
	}

	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err = manager.openSealed(tampered); err != ErrSnapshotCorrupted {
		t.Fatalf("footer tamper error = %v, want corruption", err)
	}

	bodyTampered := append([]byte(nil), sealed...)
	bodyTampered[len(snapshotHeaderMagic)+4] ^= 0xFF
	if _, err = manager.openSealed(bodyTampered); err != ErrSnapshotCorrupted {
		t.Fatalf("body tamper error = %v, want corruption", err)
	}

	truncated := sealed[:len(sealed)-10]
	if _, err = manager.openSealed(truncated); err != ErrSnapshotCorrupted {
		t.Fatalf("truncation error = %v, want corruption", err)
	}
}

func TestParseSnapshotQueryValidation(t *testing.T) {
	newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-parse", 2)

	base := func(query string) *http.Request {
		return fixture.request("/Users", query)
	}

	off, err := parseSnapshotQuery(base("count=10"), scim.ListRequestParams{Count: 10, StartIndex: 1}, userSnapshotKind)
	if err != nil || off.mode != snapshotOff {
		t.Fatalf("ordinary request misrouted: mode=%d err=%v", off.mode, err)
	}

	create, err := parseSnapshotQuery(base("snapshot=create&sortBy=displayName"), scim.ListRequestParams{Count: 10}, userSnapshotKind)
	if err != nil || create.mode != snapshotCreate || create.sortColumn != "display_name" || create.descending {
		t.Fatalf("create query parsed wrong: %#v err=%v", create, err)
	}

	badSort, err := parseSnapshotQuery(base("snapshot=create&sortBy=password"), scim.ListRequestParams{Count: 10}, userSnapshotKind)
	if err == nil || badSort != nil {
		t.Fatal("unsupported sortBy must be rejected")
	}

	_, err = parseSnapshotQuery(base("snapshot=create&sortBy=userName&sortOrder=sideways"),
		scim.ListRequestParams{Count: 10}, userSnapshotKind)
	if err == nil {
		t.Fatal("invalid sortOrder must be rejected")
	}

	_, err = parseSnapshotQuery(base("snapshot=create&attributes=userName&excludedAttributes=emails"),
		scim.ListRequestParams{Count: 10}, userSnapshotKind)
	if err == nil {
		t.Fatal("attributes together with excludedAttributes must be rejected")
	}

	tokenRequest := httptest.NewRequest(http.MethodGet, "/Users?snapshotToken=abc123", nil)
	tokenRequest = WithOrganization(tokenRequest, fixture.org)
	tokenRequest = WithSubject(tokenRequest, fixture.subject)
	consume, err := parseSnapshotQuery(tokenRequest, scim.ListRequestParams{Count: 10}, userSnapshotKind)
	if err != nil || consume.mode != snapshotConsume || consume.token != "abc123" {
		t.Fatalf("consume query parsed wrong: %#v err=%v", consume, err)
	}

	if _, err = parseSnapshotQuery(base("snapshot=wat"), scim.ListRequestParams{Count: 10}, userSnapshotKind); err == nil {
		t.Fatal("unknown snapshot mode must be rejected")
	}
}

func TestSnapshotDisabledByConfig(t *testing.T) {
	previous, existed := os.LookupEnv("scimSnapshotEnabled")
	_ = os.Setenv("scimSnapshotEnabled", "false")
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv("scimSnapshotEnabled", previous)
		} else {
			_ = os.Unsetenv("scimSnapshotEnabled")
		}
	})

	if manager := getSnapshotManager(); manager != nil {
		t.Fatal("the extension must stay dormant when scimSnapshotEnabled is not true")
	}
}

func TestSnapshotEnvelopeExpiryEnforced(t *testing.T) {
	manager := newTestManager(t, snapshotConfig{ttl: 40 * time.Millisecond})
	env := &snapshotEnvelope{
		SchemaVersion: SnapshotSchemaVersion,
		ResourceType:  "User",
		Organization:  "org-expiry",
		Subject:       "org-expiry/admin",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(40 * time.Millisecond),
		TotalResults:  0,
		Resources:     []scim.Resource{},
	}
	token, err := manager.create(env)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	entry, release, err := manager.acquire(token)
	if err != nil {
		t.Fatalf("acquire fresh token: %v", err)
	}
	if _, err = manager.read(entry); err != nil {
		t.Fatalf("fresh snapshot unreadable: %v", err)
	}
	release()

	time.Sleep(80 * time.Millisecond)
	if _, _, err = manager.acquire(token); err != ErrSnapshotExpired {
		t.Fatalf("expiry error = %v, want ErrSnapshotExpired", err)
	}
}
