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
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/scim2/filter-parser/v2"
	"github.com/xorm-io/xorm"
)

var (
	testHelperEngine  *xorm.Engine
	testHelperAdapter *object.Ormer
	fixtureSeq        atomic.Uint64
)

// uniqueOrg makes every fixture use its own organization, so repeated test runs inside
// one process (go test -count=N) never collide on the (owner, name) primary key.
func uniqueOrg(name string) string {
	return fmt.Sprintf("%s-%d", name, fixtureSeq.Add(1))
}

func TestMain(m *testing.M) {
	tempDir, err := os.MkdirTemp("", "scim-snapshot-db-*")
	if err != nil {
		panic(err)
	}
	dbPath := filepath.Join(tempDir, "scim-snapshot.db")
	dsn := dbPath + "?_pragma=busy_timeout(5000)"

	_ = os.Setenv("driverName", "sqlite")
	_ = os.Setenv("dataSourceName", dsn)
	_ = os.Setenv("tableNamePrefix", "")
	_ = os.Setenv("scimSnapshotEnabled", "true")

	object.InitAdapter()
	object.CreateTables()

	adapter, err := object.NewAdapter("sqlite", dsn, "")
	if err != nil {
		panic(err)
	}
	// Retain the Ormer itself, otherwise its finalizer closes the engine underneath us.
	testHelperAdapter = adapter
	testHelperEngine = adapter.Engine

	code := m.Run()
	_ = testHelperEngine.Close()
	_ = os.RemoveAll(tempDir)
	os.Exit(code)
}

type orgFixture struct {
	org     string
	subject string
	admin   *object.User
	users   []*object.User
	groups  []*object.Group
}

func newTestManager(t *testing.T, cfg snapshotConfig) *snapshotManager {
	t.Helper()
	cfg.enabled = true
	if cfg.dir == "" {
		cfg.dir = t.TempDir()
	}
	if cfg.ttl == 0 {
		cfg.ttl = time.Minute
	}
	if cfg.sweepInterval == 0 {
		cfg.sweepInterval = time.Hour
	}
	if cfg.maxResources == 0 {
		cfg.maxResources = 1000
	}
	if cfg.maxBytes == 0 {
		cfg.maxBytes = 8 * 1024 * 1024
	}
	if cfg.maxPerOrg == 0 {
		cfg.maxPerOrg = 8
	}
	manager, err := newSnapshotManager(cfg)
	if err != nil {
		t.Fatalf("newSnapshotManager: %v", err)
	}
	t.Cleanup(manager.Close)

	defaultSnapshotManagerLock.Lock()
	previous := defaultSnapshotManager
	defaultSnapshotManager = manager
	defaultSnapshotManagerLock.Unlock()
	t.Cleanup(func() {
		defaultSnapshotManagerLock.Lock()
		defaultSnapshotManager = previous
		defaultSnapshotManagerLock.Unlock()
	})
	return manager
}

func newOrgFixture(t *testing.T, org string, userCount int) *orgFixture {
	t.Helper()
	org = uniqueOrg(org)
	admin := &object.User{
		Owner:       org,
		Name:        "admin",
		Id:          org + "-admin-id",
		DisplayName: "Org Admin",
		Email:       "admin@" + org + ".test",
		IsAdmin:     true,
		CreatedTime: "2026-01-01T00:00:00Z",
		UpdatedTime: "2026-01-01T00:00:00Z",
	}
	users := []*object.User{admin}
	for i := 0; i < userCount; i++ {
		// Every third user shares a display name and every user shares a created time,
		// so the unique id tie-breaker is the only thing stabilizing the order.
		displayName := fmt.Sprintf("Dup %d", i%3)
		users = append(users, &object.User{
			Owner:       org,
			Name:        fmt.Sprintf("user%02d", i),
			Id:          fmt.Sprintf("%s-uid-%02d", org, i),
			DisplayName: displayName,
			Email:       fmt.Sprintf("secret-%s-user%02d@example.test", org, i),
			Phone:       fmt.Sprintf("1390000%04d", i),
			Homepage:    "https://example.test/" + org,
			Type:        "normal-user",
			CreatedTime: "2026-02-02T02:02:02Z",
			UpdatedTime: "2026-02-02T02:02:02Z",
		})
	}
	if _, err := testHelperEngine.Insert(users); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	return &orgFixture{
		org:     org,
		subject: admin.GetId(),
		admin:   admin,
		users:   users[1:],
	}
}

func (f *orgFixture) addGroups(t *testing.T, count int) {
	t.Helper()
	groups := make([]*object.Group, 0, count)
	for i := 0; i < count; i++ {
		groups = append(groups, &object.Group{
			Owner:       f.org,
			Name:        fmt.Sprintf("group%02d", i),
			DisplayName: fmt.Sprintf("Group Dup %d", i%2),
			CreatedTime: "2026-02-02T02:02:02Z",
			UpdatedTime: "2026-02-02T02:02:02Z",
			IsTopGroup:  true,
			IsEnabled:   true,
		})
	}
	if _, err := testHelperEngine.Insert(groups); err != nil {
		t.Fatalf("insert groups: %v", err)
	}
	f.groups = groups
}

func (f *orgFixture) request(endpoint, rawQuery string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, endpoint+"?"+rawQuery, nil)
	r = WithOrganization(r, f.org)
	r = WithSubject(r, f.subject)
	return WithHeaderSink(r, &HeaderSink{})
}

func buildParams(t *testing.T, startIndex, count int, filterExpr string) scim.ListRequestParams {
	t.Helper()
	params := scim.ListRequestParams{StartIndex: startIndex, Count: count}
	if filterExpr != "" {
		expr, err := filter.ParseFilter([]byte(filterExpr))
		if err != nil {
			t.Fatalf("parse filter %q: %v", filterExpr, err)
		}
		params.Filter = expr
	}
	return params
}

func listUsers(t *testing.T, r *http.Request, params scim.ListRequestParams) (scim.Page, string) {
	t.Helper()
	sink := getHeaderSink(r)
	page, err := UserResourceHandler{}.GetAll(r, params)
	if err != nil {
		t.Fatalf("GetAll users: %v", err)
	}
	token := ""
	if headers := sink.Headers(); len(headers) > 0 {
		token = headers[0][1]
	}
	return page, token
}

func listGroups(t *testing.T, r *http.Request, params scim.ListRequestParams) (scim.Page, string) {
	t.Helper()
	sink := getHeaderSink(r)
	page, err := GroupResourceHandler{}.GetAll(r, params)
	if err != nil {
		t.Fatalf("GetAll groups: %v", err)
	}
	token := ""
	if headers := sink.Headers(); len(headers) > 0 {
		token = headers[0][1]
	}
	return page, token
}

func resourceIDs(resources []scim.Resource) []string {
	ids := make([]string, 0, len(resources))
	for _, resource := range resources {
		ids = append(ids, resource.ID)
	}
	return ids
}

// attrMaps tolerates both the typed slices produced by user2resource and the generic
// map slices produced after a sealed JSON round trip.
func attrMaps(value interface{}) []map[string]interface{} {
	switch items := value.(type) {
	case []scim.ResourceAttributes:
		out := make([]map[string]interface{}, 0, len(items))
		for _, item := range items {
			out = append(out, item)
		}
		return out
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(items))
		for _, item := range items {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func attrString(attrs scim.ResourceAttributes, key string) string {
	value, _ := attrs[key].(string)
	return value
}

func urlQueryEscape(raw string) string {
	return url.QueryEscape(raw)
}

func collectUserPages(t *testing.T, f *orgFixture, token, boundQuery, filterExpr string, count int) []scim.Resource {
	t.Helper()
	var all []scim.Resource
	startIndex := 1
	for {
		query := fmt.Sprintf("snapshotToken=%s&startIndex=%d&count=%d", token, startIndex, count)
		if boundQuery != "" {
			query += "&" + boundQuery
		}
		r := f.request("/Users", query)
		page, err := UserResourceHandler{}.GetAll(r, buildParams(t, startIndex, count, filterExpr))
		if err != nil {
			t.Fatalf("paged snapshot read at %d: %v", startIndex, err)
		}
		all = append(all, page.Resources...)
		if len(page.Resources) == 0 || len(all) >= page.TotalResults {
			break
		}
		startIndex += count
	}
	return all
}

func assertScimStatus(t *testing.T, err error, status int) scimerrors.ScimError {
	t.Helper()
	scimErr, ok := err.(scimerrors.ScimError)
	if !ok {
		t.Fatalf("expected scim error, got %T: %v", err, err)
	}
	if scimErr.Status != status {
		t.Fatalf("scim status = %d (%s), want %d", scimErr.Status, scimErr.Detail, status)
	}
	return scimErr
}

func assertNoTempArtifacts(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read snapshot dir: %v", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Fatalf("aborted temp artifact was not reclaimed: %s", entry.Name())
		}
	}
}

func TestSnapshotFreezeSurvivesLaterChanges(t *testing.T) {
	newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-freeze", 14)

	createQuery := "snapshot=create&count=3&startIndex=1"
	r := fixture.request("/Users", createQuery)
	firstPage, token := listUsers(t, r, buildParams(t, 1, 3, ""))
	if token == "" {
		t.Fatal("snapshot creation did not return an opaque token")
	}
	if firstPage.TotalResults != len(fixture.users)+1 {
		t.Fatalf("TotalResults = %d, want %d", firstPage.TotalResults, len(fixture.users)+1)
	}
	if len(firstPage.Resources) != 3 {
		t.Fatalf("first page size = %d, want 3", len(firstPage.Resources))
	}

	// The complete frozen result, paged out before anything changes.
	baseline := collectUserPages(t, fixture, token, "", "", 3)
	if len(baseline) != firstPage.TotalResults {
		t.Fatalf("frozen pages cover %d resources, want %d", len(baseline), firstPage.TotalResults)
	}

	firstUser := fixture.users[0]
	deletedUser := fixture.users[len(fixture.users)-1]
	if _, err := testHelperEngine.Where("owner = ? AND name = ?", fixture.org, firstUser.Name).
		Cols("email", "display_name", "updated_time").
		Update(&object.User{Email: "changed@example.test", DisplayName: "Changed Name", UpdatedTime: "2026-03-03T03:03:03Z"}); err != nil {
		t.Fatalf("update user: %v", err)
	}
	if _, err := testHelperEngine.Delete(&object.User{Owner: fixture.org, Name: deletedUser.Name}); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, err := testHelperEngine.Insert(&object.User{
		Owner: fixture.org, Name: "latecomer", Id: fixture.org + "-latecomer",
		DisplayName: "Late Comer", Email: "late@example.test",
		CreatedTime: "2026-04-04T04:04:04Z", UpdatedTime: "2026-04-04T04:04:04Z",
	}); err != nil {
		t.Fatalf("insert late user: %v", err)
	}

	frozen := collectUserPages(t, fixture, token, "", "", 3)
	if got := resourceIDs(frozen); !slices.Equal(got, resourceIDs(baseline)) {
		t.Fatalf("frozen ordering drifted after writes: %v vs %v", got, resourceIDs(baseline))
	}
	if slices.Contains(resourceIDs(frozen), fixture.org+"-latecomer") {
		t.Fatal("a user created after the freeze leaked into the snapshot")
	}
	var changedStillFrozen, deletedStillFrozen bool
	for _, resource := range frozen {
		if resource.ID == firstUser.Id {
			emails := attrMaps(resource.Attributes["emails"])
			if len(emails) != 1 || emails[0]["value"] != firstUser.Email {
				t.Fatal("the snapshot returned the post-update email instead of the frozen value")
			}
			changedStillFrozen = true
		}
		if resource.ID == deletedUser.Id {
			deletedStillFrozen = true
		}
	}
	if !changedStillFrozen {
		t.Fatal("the updated user vanished from the frozen pages")
	}
	if !deletedStillFrozen {
		t.Fatal("a user deleted after the freeze disappeared from the snapshot")
	}

	// The ordinary list path keeps reading live data and sees the new total.
	livePage, liveToken := listUsers(t, fixture.request("/Users", "count=100"), buildParams(t, 1, 100, ""))
	if liveToken != "" {
		t.Fatal("an ordinary list request must not mint a snapshot token")
	}
	if livePage.TotalResults != firstPage.TotalResults {
		t.Fatalf("live TotalResults = %d, want changed total %d", livePage.TotalResults, firstPage.TotalResults)
	}
}

func TestSnapshotStableOrderWithDuplicateSortValues(t *testing.T) {
	newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-dups", 11)
	boundQuery := "sortBy=displayName&sortOrder=ascending"

	_, tokenA := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=4&"+boundQuery),
		buildParams(t, 1, 4, ""))
	_, tokenB := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=4&"+boundQuery),
		buildParams(t, 1, 4, ""))

	orderA := resourceIDs(collectUserPages(t, fixture, tokenA, boundQuery, "", 4))
	orderB := resourceIDs(collectUserPages(t, fixture, tokenB, boundQuery, "", 4))
	if !slices.Equal(orderA, orderB) {
		t.Fatalf("duplicate sort values produced unstable orders: %v vs %v", orderA, orderB)
	}

	unique := make(map[string]struct{}, len(orderA))
	for _, id := range orderA {
		if _, duplicated := unique[id]; duplicated {
			t.Fatalf("resource %s appeared twice across the pages", id)
		}
		unique[id] = struct{}{}
	}
	if len(unique) != len(fixture.users)+1 {
		t.Fatalf("pages cover %d unique resources, want %d", len(unique), len(fixture.users)+1)
	}

	// Equal display names must be ordered by the unique id tie-breaker.
	page, _ := listUsers(t,
		fixture.request("/Users", "snapshotToken="+tokenA+"&startIndex=1&count=100&"+boundQuery),
		buildParams(t, 1, 100, ""))
	var previousID string
	var previousName string
	for _, resource := range page.Resources {
		name := attrString(resource.Attributes, "displayName")
		if name == previousName && resource.ID < previousID {
			t.Fatalf("tie-breaker not ascending within duplicate name %q: %s before %s", name, resource.ID, previousID)
		}
		previousID = resource.ID
		previousName = name
	}
}

func TestSnapshotFilterBindingAndCanonicalization(t *testing.T) {
	newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-filter", 9)
	filterExpr := fmt.Sprintf("userName sw \"%s\"", "user")
	boundQuery := "filter=" + urlQueryEscape(filterExpr)

	_, token := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=5&"+boundQuery),
		buildParams(t, 1, 5, filterExpr))

	// The admin does not match the filter, only the nine users do.
	page, err := UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=5&"+boundQuery),
		buildParams(t, 1, 5, filterExpr))
	if err != nil {
		t.Fatalf("consume with identical filter: %v", err)
	}
	if page.TotalResults != len(fixture.users) {
		t.Fatalf("filtered TotalResults = %d, want %d", page.TotalResults, len(fixture.users))
	}

	// Case-insensitive attribute names canonicalize to the same binding.
	upperFilter := fmt.Sprintf("USERNAME sw \"%s\"", "user")
	page, err = UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=5&filter="+urlQueryEscape(upperFilter)),
		buildParams(t, 1, 5, upperFilter))
	if err != nil {
		t.Fatalf("equivalent filter with different casing rejected: %v", err)
	}
	if page.TotalResults != len(fixture.users) {
		t.Fatalf("canonicalized filter TotalResults = %d, want %d", page.TotalResults, len(fixture.users))
	}

	changedFilter := fmt.Sprintf("userName sw \"%s\"", "admin")
	_, err = UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=5&filter="+urlQueryEscape(changedFilter)),
		buildParams(t, 1, 5, changedFilter))
	assertScimStatus(t, err, http.StatusForbidden)

	// Sorting changes the frozen query and must be rejected.
	_, err = UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=5&sortBy=userName"),
		buildParams(t, 1, 5, ""))
	assertScimStatus(t, err, http.StatusForbidden)

	// A forged or unknown token is never an authorization credential.
	_, err = UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken=forged-not-a-real-token&startIndex=1&count=5"),
		buildParams(t, 1, 5, ""))
	assertScimStatus(t, err, http.StatusForbidden)
}

func TestSnapshotAttributeProjectionAndDiskSecrecy(t *testing.T) {
	manager := newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-attrs", 6)

	includeQuery := "attributes=userName,emails.value"
	page, token := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=100&"+includeQuery),
		buildParams(t, 1, 100, ""))
	for _, resource := range page.Resources {
		if _, ok := resource.Attributes["userName"]; !ok {
			t.Fatal("whitelisted userName attribute missing")
		}
		if _, ok := resource.Attributes["displayName"]; ok {
			t.Fatal("non-whitelisted displayName attribute was projected into the artifact")
		}
		emails := attrMaps(resource.Attributes["emails"])
		if len(emails) != 1 {
			t.Fatalf("emails projection malformed: %#v", resource.Attributes["emails"])
		}
		if _, ok := emails[0]["value"]; !ok {
			t.Fatal("emails.value sub-attribute missing")
		}
		if len(emails[0]) != 1 {
			t.Fatalf("emails container leaked sub-attributes: %#v", emails[0])
		}
	}

	// The sealed file is encrypted, but the included mailbox is recoverable after
	// opening; an excluded one must never appear in the raw bytes on disk.
	entry := manager.entries[token]
	raw, err := os.ReadFile(entry.path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("artifact file is empty")
	}
	opened, err := manager.read(entry)
	if err != nil {
		t.Fatalf("read own snapshot: %v", err)
	}
	foundIncludedEmail := false
	for _, resource := range opened.Resources {
		emails := attrMaps(resource.Attributes["emails"])
		if len(emails) == 1 && emails[0]["value"] == fixture.users[0].Email {
			foundIncludedEmail = true
		}
	}
	if !foundIncludedEmail {
		t.Fatal("included email did not survive the sealed round trip")
	}

	excludeQuery := "excludedAttributes=emails,phoneNumbers"
	_, excludedToken := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=100&"+excludeQuery),
		buildParams(t, 1, 100, ""))
	excludedEntry := manager.entries[excludedToken]
	excludedRaw, err := os.ReadFile(excludedEntry.path)
	if err != nil {
		t.Fatalf("read excluded artifact: %v", err)
	}
	for _, secret := range []string{fixture.users[0].Email, fixture.users[0].Phone} {
		if bytes.Contains(excludedRaw, []byte(secret)) {
			t.Fatal("a sensitive excluded attribute was written into the sealed artifact")
		}
	}
	excludedEnv, err := manager.read(excludedEntry)
	if err != nil {
		t.Fatalf("open excluded artifact: %v", err)
	}
	for _, resource := range excludedEnv.Resources {
		if _, ok := resource.Attributes["emails"]; ok {
			t.Fatal("excluded emails attribute survived projection")
		}
		if _, ok := resource.Attributes["phoneNumbers"]; ok {
			t.Fatal("excluded phoneNumbers attribute survived projection")
		}
		if _, ok := resource.Attributes["userName"]; !ok {
			t.Fatal("a non-excluded attribute was removed")
		}
	}

	// Enterprise extension projection keeps the extension container only.
	extQuery := "attributes=" + UserExtensionKey + ",userName"
	extPage, _ := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=100&"+extQuery),
		buildParams(t, 1, 100, ""))
	for _, resource := range extPage.Resources {
		if _, ok := resource.Attributes[UserExtensionKey]; !ok {
			t.Fatal("whitelisted enterprise extension missing")
		}
		if len(resource.Attributes) != 2 {
			t.Fatalf("extension projection leaked attributes: %v", resource.Attributes)
		}
	}
}

func TestSnapshotPermissionRevocationAndScope(t *testing.T) {
	newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-perm", 5)
	_, token := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=4"),
		buildParams(t, 1, 4, ""))

	consume := func(org, subject string) error {
		r := httptest.NewRequest(http.MethodGet, "/Users?snapshotToken="+token+"&startIndex=1&count=4", nil)
		r = WithOrganization(r, org)
		r = WithSubject(r, subject)
		_, err := UserResourceHandler{}.GetAll(r, buildParams(t, 1, 4, ""))
		return err
	}

	// Another organization may not ride the token.
	_, err := UserResourceHandler{}.GetAll(
		WithOrganization(fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=4"), "other-org"),
		buildParams(t, 1, 4, ""))
	assertScimStatus(t, err, http.StatusForbidden)

	// Another subject may not ride the token.
	if err = consume(fixture.org, fixture.org+"/someone-else"); err == nil {
		t.Fatal("a foreign subject consumed the snapshot")
	} else {
		assertScimStatus(t, err, http.StatusForbidden)
	}

	// Revoking the admin role changes the permission generation immediately.
	if _, err = testHelperEngine.Where("owner = ? AND name = ?", fixture.org, "admin").
		Cols("is_admin").Update(&object.User{IsAdmin: false}); err != nil {
		t.Fatalf("revoke admin: %v", err)
	}
	assertScimStatus(t, consume(fixture.org, fixture.subject), http.StatusForbidden)

	if _, err = testHelperEngine.Where("owner = ? AND name = ?", fixture.org, "admin").
		Cols("is_admin", "updated_time").
		Update(&object.User{IsAdmin: true, UpdatedTime: "2026-05-05T05:05:05Z"}); err != nil {
		t.Fatalf("restore admin: %v", err)
	}
	assertScimStatus(t, consume(fixture.org, fixture.subject), http.StatusForbidden)
}

func TestSnapshotCorruptionAndExpiry(t *testing.T) {
	manager := newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-corrupt", 4)
	_, token := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=3"),
		buildParams(t, 1, 3, ""))
	entry := manager.entries[token]

	original, err := os.ReadFile(entry.path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	tampered := append([]byte(nil), original...)
	tampered[len(tampered)/2] ^= 0xFF
	if err = os.WriteFile(entry.path, tampered, 0o600); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}
	_, err = UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=3"),
		buildParams(t, 1, 3, ""))
	assertScimStatus(t, err, http.StatusBadRequest)

	truncated := append([]byte(nil), original[:len(original)/2]...)
	if err = os.WriteFile(entry.path, truncated, 0o600); err != nil {
		t.Fatalf("truncate artifact: %v", err)
	}
	_, err = UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=3"),
		buildParams(t, 1, 3, ""))
	assertScimStatus(t, err, http.StatusBadRequest)

	if err = os.WriteFile(entry.path, original, 0o600); err != nil {
		t.Fatalf("restore artifact: %v", err)
	}
	page, err := UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=3"),
		buildParams(t, 1, 3, ""))
	if err != nil {
		t.Fatalf("intact artifact rejected: %v", err)
	}
	if page.TotalResults != len(fixture.users)+1 {
		t.Fatalf("restored TotalResults = %d", page.TotalResults)
	}

	// count=0 keeps reporting the fixed TotalResults without materializing a page.
	countZero, err := UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=0"),
		buildParams(t, 1, 0, ""))
	if err != nil {
		t.Fatalf("count=0 read: %v", err)
	}
	if countZero.TotalResults != page.TotalResults || countZero.Resources != nil {
		t.Fatalf("count=0 page = %#v, want fixed total and no resources", countZero)
	}

	expiredManager := newTestManager(t, snapshotConfig{ttl: 60 * time.Millisecond, sweepInterval: time.Hour})
	expiredFixture := newOrgFixture(t, "snap-expired", 3)
	_, expiredToken := listUsers(t,
		expiredFixture.request("/Users", "snapshot=create&count=2"),
		buildParams(t, 1, 2, ""))
	expiredPath := filepath.Join(expiredManager.cfg.dir, expiredToken+snapshotFileSuffix)
	time.Sleep(120 * time.Millisecond)
	_, err = UserResourceHandler{}.GetAll(
		expiredFixture.request("/Users", "snapshotToken="+expiredToken+"&startIndex=1&count=2"),
		buildParams(t, 1, 2, ""))
	scimErr := assertScimStatus(t, err, http.StatusBadRequest)
	if scimErr != ErrSnapshotExpired {
		t.Fatalf("expired token returned %s, want explicit expiry error", scimErr.Detail)
	}
	expiredManager.sweep()
	if _, ok := expiredManager.entries[expiredToken]; ok {
		t.Fatal("janitor did not drop the expired entry")
	}
	if _, err = os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Fatalf("expired artifact not reclaimed: %v", err)
	}
}

func TestSnapshotBoundsAndRelease(t *testing.T) {
	manager := newTestManager(t, snapshotConfig{maxResources: 3, maxPerOrg: 1})
	fixture := newOrgFixture(t, "snap-bounds", 6)

	_, err := UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshot=create&count=2"),
		buildParams(t, 1, 2, ""))
	assertScimStatus(t, err, http.StatusBadRequest)

	smallFixture := newOrgFixture(t, "snap-bounds-small", 2)
	_, token := listUsers(t,
		smallFixture.request("/Users", "snapshot=create&count=2"),
		buildParams(t, 1, 2, ""))

	// Per-organization concurrency bound: a second live snapshot is refused.
	_, err = UserResourceHandler{}.GetAll(
		smallFixture.request("/Users", "snapshot=create&count=2"),
		buildParams(t, 1, 2, ""))
	assertScimStatus(t, err, http.StatusBadRequest)

	entry, release, err := manager.acquire("missing-token")
	if err != ErrSnapshotTokenInvalid {
		t.Fatalf("unknown token error = %v, want ErrSnapshotTokenInvalid", err)
	}
	if entry != nil || release != nil {
		t.Fatal("unknown token returned a reader slot")
	}

	// Releasing while a reader holds the slot is refused instead of deleting under it.
	activeEntry, activeRelease, err := manager.acquire(token)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err = manager.release(token, smallFixture.subject); err == nil {
		t.Fatal("release succeeded while a reader was active")
	} else {
		assertScimStatus(t, err, http.StatusConflict)
	}
	activeRelease()

	if err = manager.release(token, smallFixture.subject); err != nil {
		t.Fatalf("release after readers drained: %v", err)
	}
	if _, _, err = manager.acquire(token); err != ErrSnapshotTokenInvalid {
		t.Fatalf("released token error = %v, want invalid token", err)
	}
	if _, err = os.Stat(activeEntry.path); !os.IsNotExist(err) {
		t.Fatalf("released artifact still on disk: %v", err)
	}
	assertNoTempArtifacts(t, manager.cfg.dir)

	// Byte bound.
	byteManager := newTestManager(t, snapshotConfig{maxBytes: 64})
	byteFixture := newOrgFixture(t, "snap-bytes", 2)
	_, err = UserResourceHandler{}.GetAll(
		byteFixture.request("/Users", "snapshot=create&count=2"),
		buildParams(t, 1, 2, ""))
	assertScimStatus(t, err, http.StatusBadRequest)
	assertNoTempArtifacts(t, byteManager.cfg.dir)
}

func TestSnapshotConcurrentReaders(t *testing.T) {
	manager := newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-concurrent", 13)
	_, token := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=5"),
		buildParams(t, 1, 5, ""))

	baseline := resourceIDs(collectUserPages(t, fixture, token, "", "", 5))

	const goroutines = 20
	var waitGroup sync.WaitGroup
	errorsCh := make(chan error, goroutines)
	waitGroup.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer waitGroup.Done()
			got := resourceIDs(collectUserPages(t, fixture, token, "", "", 5))
			if !slices.Equal(got, baseline) {
				errorsCh <- fmt.Errorf("concurrent reader saw a different frozen order")
			}
		}()
	}
	waitGroup.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatal(err)
	}

	if err := manager.release(token, fixture.subject); err != nil {
		t.Fatalf("release after concurrent reads: %v", err)
	}
	assertNoTempArtifacts(t, manager.cfg.dir)
}

func TestSnapshotGroupsFrozen(t *testing.T) {
	newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-groups", 0)
	fixture.addGroups(t, 7)
	boundQuery := "sortBy=displayName&sortOrder=ascending"

	page, token := listGroups(t,
		fixture.request("/Groups", "snapshot=create&count=3&"+boundQuery),
		buildParams(t, 1, 3, ""))
	if token == "" || page.TotalResults != len(fixture.groups) {
		t.Fatalf("group snapshot page = %#v token = %q", page, token)
	}

	baseline := collectGroupPages(t, fixture, token, boundQuery, 3)
	if _, err := testHelperEngine.Where("owner = ? AND name = ?", fixture.org, fixture.groups[0].Name).
		Cols("display_name", "updated_time").
		Update(&object.Group{DisplayName: "Renamed Group", UpdatedTime: "2026-06-06T06:06:06Z"}); err != nil {
		t.Fatalf("rename group: %v", err)
	}
	if _, err := testHelperEngine.Delete(&object.Group{Owner: fixture.org, Name: fixture.groups[len(fixture.groups)-1].Name}); err != nil {
		t.Fatalf("delete group: %v", err)
	}

	frozen := collectGroupPages(t, fixture, token, boundQuery, 3)
	if !slices.Equal(resourceIDs(frozen), resourceIDs(baseline)) {
		t.Fatal("group snapshot drifted after writes")
	}
	for _, resource := range frozen {
		if resource.ID == fixture.groups[0].GetId() {
			if resource.Attributes["displayName"] != fixture.groups[0].DisplayName {
				t.Fatal("group snapshot exposed the post-update display name")
			}
		}
	}

	livePage, _ := listGroups(t, fixture.request("/Groups", "count=100"), buildParams(t, 1, 100, ""))
	if livePage.TotalResults == page.TotalResults {
		t.Fatal("ordinary group list did not reflect the live deletion")
	}
}

func TestSnapshotTokenPublishedThroughHeaderSink(t *testing.T) {
	newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-header", 3)

	sink := &HeaderSink{}
	r := httptest.NewRequest(http.MethodGet, "/Users?snapshot=create&count=2", nil)
	r = WithOrganization(r, fixture.org)
	r = WithSubject(r, fixture.subject)
	r = WithHeaderSink(r, sink)

	if _, err := (UserResourceHandler{}).GetAll(r, buildParams(t, 1, 2, "")); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	recorder := httptest.NewRecorder()
	for _, header := range sink.Headers() {
		recorder.Header().Set(header[0], header[1])
	}
	if token := recorder.Header().Get(SnapshotTokenHeader); token == "" {
		t.Fatal("the opaque snapshot token was not published through the header sink")
	}
}

func TestSnapshotReleaseOverHTTP(t *testing.T) {
	newTestManager(t, snapshotConfig{})
	fixture := newOrgFixture(t, "snap-release-http", 3)
	_, token := listUsers(t,
		fixture.request("/Users", "snapshot=create&count=2"),
		buildParams(t, 1, 2, ""))

	recorder := httptest.NewRecorder()
	releaseRequest := fixture.request("/Users", "snapshot=release&snapshotToken="+token)
	if !HandleSnapshotRelease(recorder, releaseRequest) {
		t.Fatal("the release request was not intercepted")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("release status = %d, want 204", recorder.Code)
	}

	_, err := UserResourceHandler{}.GetAll(
		fixture.request("/Users", "snapshotToken="+token+"&startIndex=1&count=2"),
		buildParams(t, 1, 2, ""))
	assertScimStatus(t, err, http.StatusForbidden)

	// A request without the release mode falls through to the ordinary SCIM dispatch.
	plainRequest := fixture.request("/Users", "startIndex=1&count=2")
	if HandleSnapshotRelease(httptest.NewRecorder(), plainRequest) {
		t.Fatal("an ordinary list request must not be treated as a release")
	}
}

func collectGroupPages(t *testing.T, fixture *orgFixture, token, boundQuery string, count int) []scim.Resource {
	t.Helper()
	var all []scim.Resource
	startIndex := 1
	for {
		query := fmt.Sprintf("snapshotToken=%s&startIndex=%d&count=%d", token, startIndex, count)
		if boundQuery != "" {
			query += "&" + boundQuery
		}
		r := fixture.request("/Groups", query)
		page, err := GroupResourceHandler{}.GetAll(r, buildParams(t, startIndex, count, ""))
		if err != nil {
			t.Fatalf("group paged read at %d: %v", startIndex, err)
		}
		all = append(all, page.Resources...)
		if len(page.Resources) == 0 || len(all) >= page.TotalResults {
			break
		}
		startIndex += count
	}
	return all
}
