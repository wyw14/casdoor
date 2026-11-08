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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/elimity-com/scim/errors"
)

const (
	bulkTestOrg       = "scimorg"
	bulkOtherOrg      = "scimorg2"
	bulkTestWebhook   = "scim-bulk-webhook"
	bulkPatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

var (
	bulkTestOnce   sync.Once
	bulkNameSerial int64
	bulkTestDir    string
)

func TestMain(m *testing.M) {
	code := m.Run()
	object.CloseForTest()
	if bulkTestDir != "" {
		_ = os.RemoveAll(bulkTestDir)
	}
	os.Exit(code)
}

// startBulkServer boots the real SCIM handler on top of an isolated SQLite database,
// with the same organization injection the beego controller performs after RequireAdmin.
func startBulkServer(t *testing.T, scope string) *httptest.Server {
	t.Helper()
	bulkTestOnce.Do(func() { initBulkTestDatabase(t) })
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler.ServeHTTP(w, WithOrganization(r, scope))
	}))
}

func initBulkTestDatabase(t *testing.T) {
	dir, err := os.MkdirTemp("", "casdoor-scim-bulk-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	bulkTestDir = dir
	dbPath := filepath.ToSlash(filepath.Join(dir, "scim-bulk-test.db"))
	config := fmt.Sprintf(`
appname = casdoor
httpport = 8000
runmode = test
driverName = sqlite3
dataSourceName = file:%s
dbName =
logPostOnly = false
isDemoMode = false
showSql = false
defaultApplication = app-built-in
`, dbPath)
	configPath := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	if err := web.LoadAppConfig("ini", configPath); err != nil {
		t.Fatalf("load test config: %v", err)
	}

	object.InitForTest()
	object.InitDb()
	object.InitUserManager()

	for _, name := range []string{bulkTestOrg, bulkOtherOrg} {
		if _, err := object.AddOrganization(&object.Organization{
			Name:        name,
			DisplayName: name,
			CreatedTime: util.GetCurrentTime(),
		}); err != nil {
			t.Fatalf("seed organization %s: %v", name, err)
		}
		if _, err := object.AddApplication(&object.Application{
			Name:           "app-" + name,
			DisplayName:    name,
			Organization:   name,
			Cert:           "cert-built-in",
			EnablePassword: true,
			EnableSignUp:   true,
			CreatedTime:    util.GetCurrentTime(),
		}, "en"); err != nil {
			t.Fatalf("seed application for %s: %v", name, err)
		}
	}

	if _, err := object.AddWebhook(&object.Webhook{
		Owner:        "admin",
		Name:         bulkTestWebhook,
		CreatedTime:  util.GetCurrentTime(),
		Organization: bulkTestOrg,
		Url:          "http://127.0.0.1:1/scim-bulk-test",
		Method:       http.MethodPost,
		ContentType:  "application/json",
		Events: []string{
			"scim-add-user", "scim-update-user", "scim-delete-user",
			"scim-add-group", "scim-update-group", "scim-delete-group",
		},
		IsEnabled:     true,
		SingleOrgOnly: false,
	}); err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
}

func uniqueBulkName(prefix string) string {
	serial := atomic.AddInt64(&bulkNameSerial, 1)
	return fmt.Sprintf("%s%d%d", prefix, time.Now().UnixNano(), serial)
}

func bulkUserOp(bulkID, name, org string) map[string]interface{} {
	return map[string]interface{}{
		"method":  http.MethodPost,
		"bulkId":  bulkID,
		"path":    "/Users",
		"version": "v2",
		"data": map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User", UserExtensionKey},
			"userName":    name,
			"password":    "Scim@123456",
			"displayName": name,
			"emails":      []map[string]interface{}{{"value": name + "@example.com"}},
			UserExtensionKey: map[string]interface{}{
				"organization": org,
			},
		},
	}
}

func bulkGroupOp(bulkID, displayName, org string, members []map[string]interface{}) map[string]interface{} {
	data := map[string]interface{}{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group", GroupExtensionKey},
		"displayName": displayName,
		GroupExtensionKey: map[string]interface{}{
			"organization": org,
		},
	}
	if members != nil {
		data["members"] = members
	}
	return map[string]interface{}{
		"method": http.MethodPost,
		"bulkId": bulkID,
		"path":   "/Groups",
		"data":   data,
	}
}

func bulkRequest(failOnErrors int, operations ...map[string]interface{}) map[string]interface{} {
	req := map[string]interface{}{
		"schemas":    []string{bulkRequestSchema},
		"Operations": operations,
	}
	if failOnErrors > 0 {
		req["failOnErrors"] = failOnErrors
	}
	return req
}

func postBulk(t *testing.T, srv *httptest.Server, body interface{}) (int, bulkResponseBody, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal bulk request: %v", err)
	}
	resp, err := http.Post(srv.URL+"/v2/Bulk", "application/scim+json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("post bulk request: %v", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)

	var parsed bulkResponseBody
	_ = json.Unmarshal(payload, &parsed)
	return resp.StatusCode, parsed, payload
}

func doScimRequest(t *testing.T, srv *httptest.Server, method, path string, body interface{}) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, payload
}

func findBulkResponse(ops []bulkResponse, bulkID string) *bulkResponse {
	for i := range ops {
		if ops[i].BulkID == bulkID {
			return &ops[i]
		}
	}
	return nil
}

func scimErrorOf(t *testing.T, entry *bulkResponse) errors.ScimError {
	t.Helper()
	var scimErr errors.ScimError
	if err := json.Unmarshal(entry.Response, &scimErr); err != nil {
		t.Fatalf("unmarshal scim error from %s: %v", entry.BulkID, err)
	}
	return scimErr
}

func webhookEventCount(t *testing.T) int64 {
	t.Helper()
	count, err := object.GetWebhookEventCount("", "", "", "")
	if err != nil {
		t.Fatalf("count webhook events: %v", err)
	}
	return count
}

func webhookActionCounts(t *testing.T) map[string]int {
	t.Helper()
	events, err := object.GetWebhookEvents("", "", "", "", 0, 10000, "", "")
	if err != nil {
		t.Fatalf("list webhook events: %v", err)
	}
	actions := map[string]int{}
	for _, event := range events {
		actions[event.EventType]++
	}
	return actions
}

func TestBulkServiceProviderConfig(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	status, raw := doScimRequest(t, srv, http.MethodGet, "/v2/ServiceProviderConfig", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	bulk, ok := config["bulk"].(map[string]interface{})
	if !ok {
		t.Fatalf("service provider config has no bulk section: %s", raw)
	}
	if bulk["supported"] != true {
		t.Errorf("bulk.supported = %v, want true", bulk["supported"])
	}
	if int(bulk["maxOperations"].(float64)) != BulkMaxOperations {
		t.Errorf("maxOperations = %v, want %d", bulk["maxOperations"], BulkMaxOperations)
	}
	if int(bulk["maxPayloadSize"].(float64)) != BulkMaxPayloadSize {
		t.Errorf("maxPayloadSize = %v, want %d", bulk["maxPayloadSize"], BulkMaxPayloadSize)
	}
	if patch, _ := config["patch"].(map[string]interface{}); patch["supported"] != true {
		t.Errorf("patch.supported got lost: %v", config["patch"])
	}
	if filter, _ := config["filter"].(map[string]interface{}); filter["supported"] != true {
		t.Errorf("filter.supported got lost: %v", config["filter"])
	}
}

func TestBulkUserCreateAndGroupReference(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	userName := uniqueBulkName("bulk-user-")
	groupName := uniqueBulkName("bulk-group-")

	status, resp, raw := postBulk(t, srv, bulkRequest(0,
		bulkUserOp("u1", userName, bulkTestOrg),
		bulkGroupOp("g1", groupName, bulkTestOrg, []map[string]interface{}{
			{"value": "bulkId:u1", "display": userName},
		}),
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	if len(resp.Operations) != 2 {
		t.Fatalf("got %d operation responses, want 2", len(resp.Operations))
	}
	userEntry := findBulkResponse(resp.Operations, "u1")
	groupEntry := findBulkResponse(resp.Operations, "g1")
	if userEntry == nil || groupEntry == nil {
		t.Fatalf("responses lost the bulkId association: %s", raw)
	}
	if userEntry.Status != "201" || groupEntry.Status != "201" {
		t.Fatalf("unexpected statuses: user=%s group=%s", userEntry.Status, groupEntry.Status)
	}
	if groupEntry.Location == "" {
		t.Errorf("the group response has no location: %s", raw)
	}
	if bytes.Contains(raw, []byte(`"password"`)) {
		t.Errorf("the write-only password leaked into the bulk response: %s", raw)
	}

	user, err := object.GetUser(util.GetId(bulkTestOrg, userName))
	if err != nil || user == nil {
		t.Fatalf("the referenced user was not created: %v", err)
	}
	group, err := object.GetGroup(util.GetId(bulkTestOrg, groupName))
	if err != nil || group == nil {
		t.Fatalf("the group was not created: %v", err)
	}
	members, err := object.GetGroupUsers(group.GetId())
	if err != nil {
		t.Fatalf("get group members: %v", err)
	}
	if len(members) != 1 || members[0].Name != userName {
		t.Fatalf("group members = %v, want only %s", members, userName)
	}
}

func TestBulkForwardReference(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	userName := uniqueBulkName("bulk-fwd-")
	groupName := uniqueBulkName("bulk-fwd-g-")

	// The group is requested first but references the user listed later: the server must
	// create the referenced resource first while answering in the original order.
	status, resp, raw := postBulk(t, srv, bulkRequest(0,
		bulkGroupOp("g1", groupName, bulkTestOrg, []map[string]interface{}{
			{"value": "bulkId:u1"},
		}),
		bulkUserOp("u1", userName, bulkTestOrg),
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	if resp.Operations[0].BulkID != "g1" || resp.Operations[1].BulkID != "u1" {
		t.Fatalf("the response order must follow the request order: %s", raw)
	}
	groupEntry := findBulkResponse(resp.Operations, "g1")
	if groupEntry.Status != "201" {
		t.Fatalf("forward-referenced group status = %s, want 201: %s", groupEntry.Status, raw)
	}
	members, err := object.GetGroupUsers(util.GetId(bulkTestOrg, groupName))
	if err != nil {
		t.Fatalf("get group members: %v", err)
	}
	if len(members) != 1 || members[0].Name != userName {
		t.Fatalf("forward reference was not resolved to the user: %v", members)
	}
}

func TestBulkFailOnErrors(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	okName := uniqueBulkName("bulk-foe-ok-")
	stoppedName := uniqueBulkName("bulk-foe-stop-")

	invalidUser := bulkUserOp("bad", uniqueBulkName("bulk-foe-bad-"), bulkTestOrg)
	delete(invalidUser["data"].(map[string]interface{}), "userName")

	status, resp, raw := postBulk(t, srv, bulkRequest(1,
		bulkUserOp("ok", okName, bulkTestOrg),
		invalidUser,
		bulkUserOp("stopped", stoppedName, bulkTestOrg),
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	if findBulkResponse(resp.Operations, "ok").Status != "201" {
		t.Errorf("the valid operation should still succeed: %s", raw)
	}
	badEntry := findBulkResponse(resp.Operations, "bad")
	if badEntry.Status != "400" {
		t.Errorf("invalid user status = %s, want 400", badEntry.Status)
	}
	if scimErr := scimErrorOf(t, badEntry); scimErr.ScimType != "invalidValue" && scimErr.ScimType != "invalidSyntax" {
		t.Errorf("unexpected error category: %q (%s)", scimErr.ScimType, scimErr.Detail)
	}
	stoppedEntry := findBulkResponse(resp.Operations, "stopped")
	if stoppedEntry.Status == "201" {
		t.Fatalf("the operation after the failOnErrors threshold must not execute: %s", raw)
	}
	if user, _ := object.GetUser(util.GetId(bulkTestOrg, stoppedName)); user != nil {
		t.Fatalf("the stopped user was created anyway")
	}
	if user, _ := object.GetUser(util.GetId(bulkTestOrg, okName)); user == nil {
		t.Fatalf("the confirmed user must survive the threshold stop")
	}

	// Without failOnErrors the same shape processes every operation, including the last one.
	recoveredName := uniqueBulkName("bulk-foe-recover-")
	status, resp, raw = postBulk(t, srv, bulkRequest(0,
		bulkUserOp("ok2", uniqueBulkName("bulk-foe-ok2-"), bulkTestOrg),
		invalidUser,
		bulkUserOp("recovered", recoveredName, bulkTestOrg),
	))
	if status != http.StatusOK || findBulkResponse(resp.Operations, "recovered").Status != "201" {
		t.Fatalf("without failOnErrors the last operation should run: status=%d body=%s", status, raw)
	}
	if user, _ := object.GetUser(util.GetId(bulkTestOrg, recoveredName)); user == nil {
		t.Fatalf("the recovered user was not created")
	}
}

func TestBulkCrossScope(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)

	// A body that names another organization is rejected before any write.
	foreignName := uniqueBulkName("bulk-cross-")
	foreignUser := bulkUserOp("cross", foreignName, bulkOtherOrg)
	status, resp, raw := postBulk(t, srv, bulkRequest(0, foreignUser))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	entry := findBulkResponse(resp.Operations, "cross")
	if entry.Status != "403" {
		t.Fatalf("cross-organization body status = %s, want 403: %s", entry.Status, raw)
	}
	if user, _ := object.GetUser(util.GetId(bulkOtherOrg, foreignName)); user != nil {
		t.Fatalf("the cross-scope user was created")
	}

	// A path targeting a resource of another organization is invisible to the scoped request.
	seedName := uniqueBulkName("bulk-seed-")
	seedUser := &object.User{
		Owner:       bulkOtherOrg,
		Name:        seedName,
		Password:    "Scim@123456",
		DisplayName: seedName,
		CreatedTime: util.GetCurrentTime(),
		UpdatedTime: util.GetCurrentTime(),
	}
	if _, err := object.AddUser(seedUser, "en"); err != nil {
		t.Fatalf("seed foreign user: %v", err)
	}
	path := "/Users/" + url.PathEscape(seedUser.GetId())
	deleteStatus, _ := doScimRequest(t, srv, http.MethodDelete, path, nil)
	if deleteStatus != http.StatusNotFound {
		t.Errorf("cross-scope DELETE status = %d, want 404", deleteStatus)
	}

	// A reference cannot escape either: the foreign user operation fails and the group that
	// references it fails with a per-operation reference error instead of being created.
	groupName := uniqueBulkName("bulk-cross-g-")
	status, resp, raw = postBulk(t, srv, bulkRequest(0,
		bulkUserOp("foreign", uniqueBulkName("bulk-cross-ref-"), bulkOtherOrg),
		bulkGroupOp("group", groupName, bulkTestOrg, []map[string]interface{}{
			{"value": "bulkId:foreign"},
		}),
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	if findBulkResponse(resp.Operations, "foreign").Status != "403" {
		t.Errorf("foreign user op should be 403: %s", raw)
	}
	groupEntry := findBulkResponse(resp.Operations, "group")
	if groupEntry.Status == "201" {
		t.Fatalf("the group referencing a foreign resource must not be created: %s", raw)
	}
	if group, _ := object.GetGroup(util.GetId(bulkTestOrg, groupName)); group != nil {
		t.Fatalf("the cross-scope group exists")
	}

	// The global admin scope (empty organization) is not bound to a single organization.
	globalSrv := startBulkServer(t, "")
	globalName := uniqueBulkName("bulk-global-")
	status, resp, raw = postBulk(t, globalSrv, bulkRequest(0, bulkUserOp("g", globalName, bulkOtherOrg)))
	if status != http.StatusOK || findBulkResponse(resp.Operations, "g").Status != "201" {
		t.Fatalf("global admin scope should allow the other organization: status=%d body=%s", status, raw)
	}
}

func TestBulkDuplicateBulkId(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	first := uniqueBulkName("bulk-dup-1-")
	second := uniqueBulkName("bulk-dup-2-")

	status, resp, raw := postBulk(t, srv, bulkRequest(0,
		bulkUserOp("same", first, bulkTestOrg),
		bulkUserOp("same", second, bulkTestOrg),
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	var duplicates []*bulkResponse
	for i := range resp.Operations {
		if resp.Operations[i].BulkID == "same" {
			duplicates = append(duplicates, &resp.Operations[i])
		}
	}
	if len(duplicates) != 2 {
		t.Fatalf("both duplicate operations must stay associated with their bulkId: %s", raw)
	}
	if duplicates[0].Status != "400" || duplicates[1].Status != "400" {
		t.Fatalf("duplicate bulkId statuses = %s/%s, want 400/400", duplicates[0].Status, duplicates[1].Status)
	}
	for _, name := range []string{first, second} {
		if user, _ := object.GetUser(util.GetId(bulkTestOrg, name)); user != nil {
			t.Fatalf("the user %s was created despite the duplicate bulkId", name)
		}
	}
}

func TestBulkMissingAndCircularReferences(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)

	// Missing reference: the invalid group fails per-operation, the independent user still succeeds.
	userName := uniqueBulkName("bulk-miss-u-")
	missingGroup := uniqueBulkName("bulk-miss-g-")
	status, resp, raw := postBulk(t, srv, bulkRequest(0,
		bulkUserOp("u1", userName, bulkTestOrg),
		bulkGroupOp("g1", missingGroup, bulkTestOrg, []map[string]interface{}{
			{"value": "bulkId:ghost"},
		}),
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	if findBulkResponse(resp.Operations, "u1").Status != "201" {
		t.Errorf("the independent user should succeed: %s", raw)
	}
	missingEntry := findBulkResponse(resp.Operations, "g1")
	if missingEntry.Status != "400" {
		t.Fatalf("missing reference status = %s, want 400", missingEntry.Status)
	}
	if scimErr := scimErrorOf(t, missingEntry); scimErr.ScimType != "invalidValue" {
		t.Errorf("missing reference error category = %q, want invalidValue", scimErr.ScimType)
	}
	if group, _ := object.GetGroup(util.GetId(bulkTestOrg, missingGroup)); group != nil {
		t.Fatalf("the group with a missing reference was created")
	}

	// Circular reference between two groups.
	groupA := uniqueBulkName("bulk-cyc-a-")
	groupB := uniqueBulkName("bulk-cyc-b-")
	status, resp, raw = postBulk(t, srv, bulkRequest(0,
		bulkGroupOp("a", groupA, bulkTestOrg, []map[string]interface{}{{"value": "bulkId:b"}}),
		bulkGroupOp("b", groupB, bulkTestOrg, []map[string]interface{}{{"value": "bulkId:a"}}),
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	for _, bulkID := range []string{"a", "b"} {
		entry := findBulkResponse(resp.Operations, bulkID)
		if entry.Status != "400" {
			t.Errorf("circular op %s status = %s, want 400", bulkID, entry.Status)
		}
	}
	for _, name := range []string{groupA, groupB} {
		if group, _ := object.GetGroup(util.GetId(bulkTestOrg, name)); group != nil {
			t.Fatalf("the circular group %s was created", name)
		}
	}
}

func TestBulkCancellation(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	const total = 8
	ops := make([]map[string]interface{}, 0, total)
	names := make([]string, 0, total)
	for i := 0; i < total; i++ {
		name := uniqueBulkName("bulk-cancel-")
		names = append(names, name)
		ops = append(ops, bulkUserOp(fmt.Sprintf("u%d", i), name, bulkTestOrg))
	}

	cancelCh := make(chan context.CancelFunc, 1)
	previousCtxHook, previousStepHook := bulkContextHook, bulkStepHook
	bulkContextHook = func(parent context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		cancelCh <- cancel
		return ctx, cancel
	}
	bulkStepHook = func(operationIndex int) {
		if operationIndex == 3 {
			(<-cancelCh)()
		}
	}
	defer func() {
		bulkContextHook, bulkStepHook = previousCtxHook, previousStepHook
	}()

	status, resp, raw := postBulk(t, srv, bulkRequest(0, ops...))
	if status != http.StatusOK {
		t.Fatalf("a canceled bulk request still answers 200 with the boundary, got %d: %s", status, raw)
	}
	if len(resp.Operations) != total {
		t.Fatalf("every operation must be represented, got %d", len(resp.Operations))
	}
	confirmed, notExecuted := 0, 0
	for i, entry := range resp.Operations {
		user, _ := object.GetUser(util.GetId(bulkTestOrg, names[i]))
		switch entry.Status {
		case "201":
			confirmed++
			if user == nil {
				t.Errorf("confirmed response for %s has no resource", entry.BulkID)
			}
		case "503":
			notExecuted++
			if user != nil {
				t.Errorf("not-executed response for %s but the resource exists", entry.BulkID)
			}
		default:
			t.Errorf("unexpected status %s for %s", entry.Status, entry.BulkID)
		}
	}
	if confirmed == 0 || notExecuted == 0 {
		t.Fatalf("expected a confirmed/not-executed boundary, got confirmed=%d notExecuted=%d", confirmed, notExecuted)
	}
	if confirmed+notExecuted != total {
		t.Fatalf("results were lost: confirmed=%d notExecuted=%d total=%d", confirmed, notExecuted, total)
	}
}

func TestBulkPayloadAndOperationLimits(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)

	tooMany := make([]map[string]interface{}, 0, BulkMaxOperations+1)
	for i := 0; i < BulkMaxOperations+1; i++ {
		tooMany = append(tooMany, bulkUserOp(fmt.Sprintf("u%d", i), uniqueBulkName("bulk-limit-"), bulkTestOrg))
	}
	status, _ := doScimRequest(t, srv, http.MethodPost, "/v2/Bulk", bulkRequest(0, tooMany...))
	if status != http.StatusRequestEntityTooLarge {
		t.Errorf("too many operations status = %d, want 413", status)
	}

	oversized := bulkRequest(0, bulkUserOp("big", uniqueBulkName("bulk-oversize-"), bulkTestOrg))
	padding := make([]byte, BulkMaxPayloadSize)
	for i := range padding {
		padding[i] = 'a'
	}
	oversized["padding"] = string(padding)
	status, _ = doScimRequest(t, srv, http.MethodPost, "/v2/Bulk", oversized)
	if status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized payload status = %d, want 413", status)
	}
}

func TestBulkWebhookFiresOnlyForConfirmedChanges(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	before := webhookActionCounts(t)

	user1 := uniqueBulkName("bulk-wh-u1-")
	user2 := uniqueBulkName("bulk-wh-u2-")
	groupName := uniqueBulkName("bulk-wh-g-")
	invalidUser := bulkUserOp("bad", uniqueBulkName("bulk-wh-bad-"), bulkTestOrg)
	delete(invalidUser["data"].(map[string]interface{}), "userName")

	status, _, raw := postBulk(t, srv, bulkRequest(0,
		bulkUserOp("u1", user1, bulkTestOrg),
		bulkUserOp("u2", user2, bulkTestOrg),
		bulkGroupOp("g1", groupName, bulkTestOrg, []map[string]interface{}{{"value": "bulkId:u1"}}),
		invalidUser,
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	after := webhookActionCounts(t)
	if after["scim-add-user"]-before["scim-add-user"] != 2 {
		t.Errorf("scim-add-user events delta = %d, want 2", after["scim-add-user"]-before["scim-add-user"])
	}
	if after["scim-add-group"]-before["scim-add-group"] != 1 {
		t.Errorf("scim-add-group events delta = %d, want 1", after["scim-add-group"]-before["scim-add-group"])
	}
	if total := webhookEventCount(t); total == 0 {
		t.Fatalf("no webhook events were recorded at all")
	}
}

func TestBulkPatchGroupMembers(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	userA := uniqueBulkName("bulk-patch-a-")
	userB := uniqueBulkName("bulk-patch-b-")
	groupName := uniqueBulkName("bulk-patch-g-")

	status, resp, raw := postBulk(t, srv, bulkRequest(0,
		bulkUserOp("a", userA, bulkTestOrg),
		bulkGroupOp("g", groupName, bulkTestOrg, []map[string]interface{}{{"value": "bulkId:a"}}),
	))
	if status != http.StatusOK || findBulkResponse(resp.Operations, "g").Status != "201" {
		t.Fatalf("setup bulk failed: %s", raw)
	}
	groupID := util.GetId(bulkTestOrg, groupName)

	// bulkId is transient per request, so the patched-in user is created and referenced
	// inside the same bulk request as the PATCH.
	patch := map[string]interface{}{
		"schemas": []string{bulkPatchOpSchema},
		"Operations": []map[string]interface{}{
			{
				"op":    "add",
				"path":  "members",
				"value": []map[string]interface{}{{"value": "bulkId:b"}},
			},
		},
	}
	patchOp := map[string]interface{}{
		"method": http.MethodPatch,
		"bulkId": "p1",
		"path":   "/Groups/" + url.PathEscape(groupID),
		"data":   patch,
	}
	status, resp, raw = postBulk(t, srv, bulkRequest(0,
		bulkUserOp("b", userB, bulkTestOrg),
		patchOp,
	))
	if status != http.StatusOK {
		t.Fatalf("patch bulk status = %d, body = %s", status, raw)
	}
	if findBulkResponse(resp.Operations, "b").Status != "201" {
		t.Fatalf("the referenced user was not created: %s", raw)
	}
	if findBulkResponse(resp.Operations, "p1").Status != "200" {
		t.Fatalf("patch operation failed: %s", raw)
	}
	members, err := object.GetGroupUsers(groupID)
	if err != nil {
		t.Fatalf("get group members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("the patched group should have 2 members, got %d", len(members))
	}
}

func TestBulkUniquenessConflictIsPerOperation(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	sharedName := uniqueBulkName("bulk-unique-")
	otherName := uniqueBulkName("bulk-unique-ok-")

	status, resp, raw := postBulk(t, srv, bulkRequest(0,
		bulkUserOp("u1", sharedName, bulkTestOrg),
		bulkUserOp("u2", sharedName, bulkTestOrg),
		bulkUserOp("u3", otherName, bulkTestOrg),
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	if findBulkResponse(resp.Operations, "u1").Status != "201" {
		t.Fatalf("the first user should be created: %s", raw)
	}
	conflict := findBulkResponse(resp.Operations, "u2")
	if conflict.Status != "409" {
		t.Fatalf("duplicate userName status = %s, want 409", conflict.Status)
	}
	if scimErr := scimErrorOf(t, conflict); scimErr.ScimType != "uniqueness" {
		t.Errorf("conflict error category = %q, want uniqueness", scimErr.ScimType)
	}
	// Independent transactions: the conflict neither rolls back u1 nor blocks u3.
	if findBulkResponse(resp.Operations, "u3").Status != "201" {
		t.Fatalf("the unrelated user should still succeed: %s", raw)
	}
	if user, _ := object.GetUser(util.GetId(bulkTestOrg, otherName)); user == nil {
		t.Fatalf("the unrelated user was not created")
	}
}

func TestBulkPutAndDeleteWithPathReference(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	userName := uniqueBulkName("bulk-putdel-")
	replacedName := uniqueBulkName("bulk-putdel-new-")

	putOp := map[string]interface{}{
		"method": http.MethodPut,
		"bulkId": "p1",
		"path":   "/Users/bulkId:u1",
		"data": map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User", UserExtensionKey},
			"userName":    replacedName,
			"displayName": "replaced display",
			UserExtensionKey: map[string]interface{}{
				"organization": bulkTestOrg,
			},
		},
	}
	deleteOp := map[string]interface{}{
		"method": http.MethodDelete,
		"bulkId": "d1",
		"path":   "/Users/bulkId:p1",
	}
	status, resp, raw := postBulk(t, srv, bulkRequest(0,
		bulkUserOp("u1", userName, bulkTestOrg),
		putOp,
		deleteOp,
	))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	if findBulkResponse(resp.Operations, "u1").Status != "201" {
		t.Fatalf("user create failed: %s", raw)
	}
	if findBulkResponse(resp.Operations, "p1").Status != "200" {
		t.Fatalf("PUT through a bulkId path failed: %s", raw)
	}
	if findBulkResponse(resp.Operations, "d1").Status != "204" {
		t.Fatalf("DELETE through a bulkId path failed: %s", raw)
	}
	if user, _ := object.GetUser(util.GetId(bulkTestOrg, replacedName)); user != nil {
		t.Fatalf("the replaced user should have been deleted")
	}
	// PUT replaces userName, so the original id no longer resolves.
	if user, _ := object.GetUser(util.GetId(bulkTestOrg, userName)); user != nil {
		t.Fatalf("the original user should have been replaced away")
	}
}

func TestBulkReferenceDepthIsBounded(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	groupName := uniqueBulkName("bulk-depth-")

	nested := map[string]interface{}{"leaf": "v"}
	for i := 0; i < BulkMaxReferenceDepth+2; i++ {
		nested = map[string]interface{}{"child": nested}
	}
	groupOp := bulkGroupOp("g1", groupName, bulkTestOrg, nil)
	groupOp["data"].(map[string]interface{})["nested"] = nested

	status, resp, raw := postBulk(t, srv, bulkRequest(0, groupOp))
	if status != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", status, raw)
	}
	entry := findBulkResponse(resp.Operations, "g1")
	if entry.Status != "400" {
		t.Fatalf("over-depth operation status = %s, want 400: %s", entry.Status, raw)
	}
	if scimErr := scimErrorOf(t, entry); scimErr.ScimType != "invalidValue" {
		t.Errorf("depth error category = %q, want invalidValue", scimErr.ScimType)
	}
	if group, _ := object.GetGroup(util.GetId(bulkTestOrg, groupName)); group != nil {
		t.Fatalf("the over-depth group was created")
	}
}

func TestBulkDoesNotRewriteOrdinaryStrings(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	lookalike := uniqueBulkName("bulk-look-")
	op := bulkUserOp("u1", lookalike, bulkTestOrg)
	op["data"].(map[string]interface{})["displayName"] = "bulkId:u1 should stay literal"

	status, resp, raw := postBulk(t, srv, bulkRequest(0, op))
	if status != http.StatusOK || findBulkResponse(resp.Operations, "u1").Status != "201" {
		t.Fatalf("lookalike bulk failed: %s", raw)
	}
	user, err := object.GetUser(util.GetId(bulkTestOrg, lookalike))
	if err != nil || user == nil {
		t.Fatalf("the user was not created: %v", err)
	}
	if user.DisplayName != "bulkId:u1 should stay literal" {
		t.Errorf("ordinary string was rewritten: %q", user.DisplayName)
	}
}

func TestSingleResourceScimStaysCompatible(t *testing.T) {
	srv := startBulkServer(t, bulkTestOrg)
	userName := uniqueBulkName("bulk-single-")
	groupName := uniqueBulkName("bulk-single-g-")

	// Single-resource User create/get through the same wrapper.
	createStatus, raw := doScimRequest(t, srv, http.MethodPost, "/v2/Users", map[string]interface{}{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User", UserExtensionKey},
		"userName":    userName,
		"password":    "Scim@123456",
		"displayName": userName,
		UserExtensionKey: map[string]interface{}{
			"organization": bulkTestOrg,
		},
	})
	if createStatus != http.StatusCreated {
		t.Fatalf("single user create status = %d, body = %s", createStatus, raw)
	}
	if bytes.Contains(raw, []byte(`"password"`)) {
		t.Errorf("password leaked through the single resource response")
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &created); err != nil || created.ID == "" {
		t.Fatalf("the created user has no id: %v (%s)", err, raw)
	}
	getStatus, raw := doScimRequest(t, srv, http.MethodGet, "/v2/Users/"+url.PathEscape(created.ID), nil)
	if getStatus != http.StatusOK {
		t.Fatalf("single user get status = %d, body = %s", getStatus, raw)
	}

	// Single-resource Group create with the real member, then PATCH it.
	groupStatus, raw := doScimRequest(t, srv, http.MethodPost, "/v2/Groups", map[string]interface{}{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group", GroupExtensionKey},
		"displayName": groupName,
		"members":     []map[string]interface{}{{"value": created.ID}},
		GroupExtensionKey: map[string]interface{}{
			"organization": bulkTestOrg,
		},
	})
	if groupStatus != http.StatusCreated {
		t.Fatalf("single group create status = %d, body = %s", groupStatus, raw)
	}
	groupID := util.GetId(bulkTestOrg, groupName)
	members, err := object.GetGroupUsers(groupID)
	if err != nil || len(members) != 1 || members[0].Name != userName {
		t.Fatalf("single resource group membership mismatch: %v %d", err, len(members))
	}
	patchStatus, _ := doScimRequest(t, srv, http.MethodPatch, "/v2/Groups/"+url.PathEscape(groupID), map[string]interface{}{
		"schemas": []string{bulkPatchOpSchema},
		"Operations": []map[string]interface{}{
			{"op": "remove", "path": "members"},
		},
	})
	if patchStatus != http.StatusOK {
		t.Fatalf("single group patch status = %d", patchStatus)
	}
	members, _ = object.GetGroupUsers(groupID)
	if len(members) != 0 {
		t.Fatalf("the single resource PATCH did not clear members: %d", len(members))
	}
}
