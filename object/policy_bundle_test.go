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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/casdoor/casdoor/util"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
)

// setupBundleTestDB points the global ormer at an isolated in-memory sqlite database and
// creates every table the bundle feature touches.
func setupBundleTestDB(t *testing.T) {
	t.Helper()

	ormerHandle, err := NewAdapter("sqlite3", ":memory:", "")
	if err != nil {
		t.Fatalf("failed to open the in-memory sqlite engine: %v", err)
	}
	// A single connection keeps the :memory: database shared by every session.
	ormerHandle.Engine.SetMaxOpenConns(1)
	ormer = ormerHandle
	ormer.createTable()

	_, err = xormadapter.NewAdapterByEngineWithTableName(ormer.Engine, "permission_rule", "")
	if err != nil {
		t.Fatalf("failed to create the permission_rule table: %v", err)
	}

	bundleViewStore = &policyBundleViewManager{views: map[string]*policyBundleView{}}
	bundlePublishFailureHook = nil
}

func seedBundleUser(t *testing.T, owner string, name string, groups ...string) *User {
	t.Helper()
	user := &User{Owner: owner, Name: name, Groups: groups}
	affected, err := ormer.Engine.Insert(user)
	if err != nil {
		t.Fatalf("failed to insert user %s/%s: %v", owner, name, err)
	}
	if affected == 0 {
		t.Fatalf("user %s/%s was not inserted", owner, name)
	}
	return user
}

func seedBundleRole(t *testing.T, role *Role) *Role {
	t.Helper()
	if _, err := ormer.Engine.Insert(role); err != nil {
		t.Fatalf("failed to insert role %s: %v", role.GetId(), err)
	}
	return role
}

func seedBundlePermission(t *testing.T, permission *Permission) *Permission {
	t.Helper()
	if _, err := ormer.Engine.Insert(permission); err != nil {
		t.Fatalf("failed to insert permission %s: %v", permission.GetId(), err)
	}
	// Mirror the production write path: a persisted permission always has backing
	// Casbin p rules, so the live enforcer and the bundle diff see the same baseline.
	if err := addPolicies(permission); err != nil {
		t.Fatalf("failed to seed the policies of permission %s: %v", permission.GetId(), err)
	}
	return permission
}

func seedBaselineBundle(t *testing.T, owner string) (*Role, *Permission) {
	t.Helper()
	seedBundleUser(t, owner, "alice")
	seedBundleUser(t, owner, "bob")

	role := seedBundleRole(t, &Role{
		Owner: owner, Name: "role-a", IsEnabled: true,
		Users: []string{util.GetId(owner, "alice")},
	})
	permission := seedBundlePermission(t, &Permission{
		Owner: owner, Name: "perm-1", IsEnabled: true, Effect: "allow",
		Roles:     []string{util.GetId(owner, "role-a")},
		Resources: []string{"res1"},
		Actions:   []string{"read"},
	})
	return role, permission
}

func mustPlan(t *testing.T, bundle *PolicyBundle) *PolicyBundlePlanResult {
	t.Helper()
	plan, err := PlanPolicyBundle(bundle)
	if err != nil {
		t.Fatalf("PlanPolicyBundle failed: %v", err)
	}
	if !plan.Supported {
		t.Fatalf("PlanPolicyBundle marked the bundle unsupported: %s", plan.UnsupportedReason)
	}
	return plan
}

func mustPublish(t *testing.T, bundle *PolicyBundle, digest string) *PolicyBundlePublishResult {
	t.Helper()
	result, err := PublishPolicyBundle(bundle, digest)
	if err != nil {
		t.Fatalf("PublishPolicyBundle failed: %v", err)
	}
	if result.Status != BundleGenerationPublished {
		t.Fatalf("the generation status = %s, want %s", result.Status, BundleGenerationPublished)
	}
	return result
}

func planAndPublish(t *testing.T, bundle *PolicyBundle) *PolicyBundlePublishResult {
	t.Helper()
	plan := mustPlan(t, bundle)
	return mustPublish(t, bundle, plan.Digest)
}

func permissionRuleRows(t *testing.T) []*xormadapter.CasbinRule {
	t.Helper()
	rules := []*xormadapter.CasbinRule{}
	if err := ormer.Engine.Table("permission_rule").Find(&rules); err != nil {
		t.Fatalf("failed to read permission_rule rows: %v", err)
	}
	return rules
}

func boolPtr(v bool) *bool { return &v }

func enforceRequest(t *testing.T, owner string, permissionId string, request ...interface{}) *BundleViewDecision {
	t.Helper()
	decision, err := EnforceWithBundleView(owner, permissionId, request)
	if err != nil {
		t.Fatalf("EnforceWithBundleView failed: %v", err)
	}
	if decision == nil {
		t.Fatalf("no published bundle view exists for owner %q", owner)
	}
	return decision
}

// TestPolicyBundleRenameAndPermissionSync covers the role-rename + permission
// synchronization path and compares every request decision with an independently
// rebuilt candidate enforcer.
func TestPolicyBundleRenameAndPermissionSync(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)

	request := []interface{}{util.GetId(owner, "alice"), "res1", "read"}
	baseline := &PolicyBundle{
		Owner:       owner,
		Roles:       []*Role{cloneRole(role)},
		Permissions: []*Permission{clonePermission(permission)},
		RequestCorpus: []PolicyBundleRequest{
			{PermissionId: permission.GetId(), Request: request, ExpectAllow: boolPtr(true)},
		},
	}
	gen1 := planAndPublish(t, baseline)
	if enforceRequest(t, owner, permission.GetId(), request...).Allow != true {
		t.Fatalf("the baseline generation denied a request it should allow")
	}

	// Second bundle: rename role-a to role-b and move the permission to the new role id
	// in one atomic generation.
	renamedRole := cloneRole(role)
	renamedRole.Name = "role-b"
	updatedPermission := clonePermission(permission)
	updatedPermission.Roles = []string{util.GetId(owner, "role-b")}

	renameBundle := &PolicyBundle{
		Owner: owner,
		Renames: []PolicyBundleRename{{
			Kind:  "role",
			OldId: role.GetId(),
			NewId: util.GetId(owner, "role-b"),
		}},
		Roles:       []*Role{renamedRole},
		Permissions: []*Permission{updatedPermission},
		RequestCorpus: []PolicyBundleRequest{
			{PermissionId: permission.GetId(), Request: request, ExpectAllow: boolPtr(true)},
		},
	}
	plan := mustPlan(t, renameBundle)
	for _, decision := range plan.Decisions {
		if !decision.Matched || !decision.CandidateAllow {
			t.Fatalf("the regression decision was not matched/allowed: %+v", decision)
		}
	}
	gen2 := mustPublish(t, renameBundle, plan.Digest)

	// The old role row is gone, the new one carries the user, the permission points at it.
	oldRole, err := GetRole(role.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if oldRole != nil {
		t.Fatalf("the old role %s still exists after the rename", role.GetId())
	}
	newRole, err := GetRole(util.GetId(owner, "role-b"))
	if err != nil {
		t.Fatal(err)
	}
	if newRole == nil || !util.InSlice(newRole.Users, util.GetId(owner, "alice")) {
		t.Fatalf("the renamed role was not persisted correctly: %+v", newRole)
	}
	storedPermission, err := GetPermission(permission.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if len(storedPermission.Roles) != 1 || storedPermission.Roles[0] != util.GetId(owner, "role-b") {
		t.Fatalf("the permission still references the old role: %+v", storedPermission.Roles)
	}

	// No policy row may still mention the old role subject.
	for _, rule := range permissionRuleRows(t) {
		if rule.V0 == role.GetId() {
			t.Fatalf("a stale policy row for the old role %s survived the publish: %+v", role.GetId(), rule)
		}
	}

	// The new view serves the request and labels it with the new generation.
	decision := enforceRequest(t, owner, permission.GetId(), request...)
	if !decision.Allow {
		t.Fatalf("the renamed role no longer grants the permission")
	}
	if decision.Generation != gen2.Generation {
		t.Fatalf("the decision generation = %s, want %s", decision.Generation, gen2.Generation)
	}

	// The previous generation is retired and the pointer advanced atomically.
	previous, err := GetPolicyBundleGeneration(owner, gen1.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if previous == nil || previous.Status != BundleGenerationRetired {
		t.Fatalf("the previous generation was not retired: %+v", previous)
	}
	status, currentGeneration, err := GetPolicyBundlePublishStatus(owner, "")
	if err != nil {
		t.Fatal(err)
	}
	if status != BundleGenerationPublished || currentGeneration != gen2.Generation {
		t.Fatalf("the publish status = %s/%s, want Published/%s", status, currentGeneration, gen2.Generation)
	}

	// Independent candidate enforcer: rebuild it from the persisted generation snapshot
	// and compare the decision of every corpus request with the published view. This is
	// a fully independent construction rather than a reused in-memory enforcer.
	persistedGeneration, err := GetPolicyBundleGeneration(owner, gen2.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if persistedGeneration == nil {
		t.Fatalf("the generation %s was not persisted", gen2.Generation)
	}
	persistedSnapshot := PolicyBundleSnapshot{}
	if err = json.Unmarshal([]byte(persistedGeneration.Snapshot), &persistedSnapshot); err != nil {
		t.Fatal(err)
	}
	independentCandidate := newSnapshotCandidate(&persistedSnapshot)
	candidatePermission := independentCandidate.permMap[permission.GetId()]
	if candidatePermission == nil {
		t.Fatalf("the persisted snapshot does not contain permission %s", permission.GetId())
	}
	candidateEnforcer, err := independentCandidate.buildEnforcer(candidatePermission, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, corpusRequest := range renameBundle.RequestCorpus {
		candidateAllow, err := candidateEnforcer.Enforce(util.InterfaceToEnforceArray(corpusRequest.Request)...)
		if err != nil {
			t.Fatal(err)
		}
		viewDecision := enforceRequest(t, owner, corpusRequest.PermissionId, corpusRequest.Request...)
		if candidateAllow != viewDecision.Allow {
			t.Fatalf("candidate enforcer decided %v but the published view decided %v for %v",
				candidateAllow, viewDecision.Allow, corpusRequest.Request)
		}
	}

	// Re-publishing the identical digest is idempotent and does not create a generation.
	again, err := PublishPolicyBundle(renameBundle, plan.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if again.Generation != gen2.Generation {
		t.Fatalf("the idempotent republish created generation %s instead of returning %s", again.Generation, gen2.Generation)
	}
}

// TestPolicyBundleThirdItemIllegal proves that an illegal third item aborts the plan
// with an exact path and leaves the live generation completely untouched.
func TestPolicyBundleThirdItemIllegal(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)
	gen1 := planAndPublish(t, &PolicyBundle{
		Owner:       owner,
		Roles:       []*Role{cloneRole(role)},
		Permissions: []*Permission{clonePermission(permission)},
	})

	badModel := &Model{Owner: owner, Name: "bad-model", ModelText: "this is definitely not a casbin model"}
	if _, err := ormer.Engine.Insert(badModel); err != nil {
		t.Fatal(err)
	}

	secondPermission := clonePermission(permission)
	secondPermission.Name = "perm-2"
	thirdPermission := clonePermission(permission)
	thirdPermission.Name = "perm-3"
	thirdPermission.Model = util.GetId(owner, "bad-model")

	bundle := &PolicyBundle{
		Owner: owner,
		Permissions: []*Permission{
			clonePermission(permission),
			secondPermission,
			thirdPermission,
		},
	}
	_, err := PlanPolicyBundle(bundle)
	if err == nil {
		t.Fatalf("the illegal model was not rejected")
	}
	var bundleErr *PolicyBundleError
	if !errors.As(err, &bundleErr) {
		t.Fatalf("the error type = %T, want *PolicyBundleError", err)
	}
	if !strings.HasPrefix(bundleErr.Path, "permissions[2]") {
		t.Fatalf("the error path = %q, want a permissions[2] path", bundleErr.Path)
	}

	// Publish must reject the same bundle and nothing may have changed.
	if _, err = PublishPolicyBundle(bundle, ""); err == nil {
		t.Fatalf("PublishPolicyBundle accepted the illegal bundle")
	}
	if len(permissionRuleRows(t)) == 0 {
		t.Fatalf("the live policy rows disappeared after the failed publish")
	}
	decision := enforceRequest(t, owner, permission.GetId(),
		util.GetId(owner, "alice"), "res1", "read")
	if decision.Generation != gen1.Generation || !decision.Allow {
		t.Fatalf("the live generation changed: %+v", decision)
	}
}

// TestPolicyBundleConcurrentOldView ensures readers always observe one complete
// generation: decisions are labelled either with the old or the new generation, never a
// mix of the two.
func TestPolicyBundleConcurrentOldView(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)
	gen1 := planAndPublish(t, &PolicyBundle{
		Owner:       owner,
		Roles:       []*Role{cloneRole(role)},
		Permissions: []*Permission{clonePermission(permission)},
	})

	request := []interface{}{util.GetId(owner, "alice"), "res1", "read"}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	observations := make(chan *BundleViewDecision, 256)
	errors := make(chan error, 16)

	// The collector drains decisions continuously, otherwise fast readers would fill the
	// buffer and block before the new generation is published.
	var collected []*BundleViewDecision
	var collectMu sync.Mutex
	collectorDone := make(chan struct{})
	go func() {
		for decision := range observations {
			collectMu.Lock()
			collected = append(collected, decision)
			collectMu.Unlock()
		}
		close(collectorDone)
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					decision, err := EnforceWithBundleView(owner, permission.GetId(), request)
					if err != nil {
						select {
						case errors <- err:
						case <-stop:
						}
						return
					}
					if decision != nil {
						select {
						case observations <- decision:
						case <-stop:
							return
						}
					}
				}
			}
		}()
	}

	// Give the readers a moment to settle on the old view, then publish gen2 which
	// removes "read" from the permission actions.
	time.Sleep(50 * time.Millisecond)
	updatedPermission := clonePermission(permission)
	updatedPermission.Actions = []string{"write"}
	gen2 := planAndPublish(t, &PolicyBundle{
		Owner:       owner,
		Permissions: []*Permission{updatedPermission},
	})
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(observations)
	<-collectorDone
	close(errors)

	for err := range errors {
		t.Fatalf("a concurrent reader failed: %v", err)
	}

	sawOld := false
	sawNew := false
	for _, decision := range collected {
		switch decision.Generation {
		case gen1.Generation:
			sawOld = true
			if !decision.Allow {
				t.Fatalf("the old generation returned a mixed/denied decision")
			}
		case gen2.Generation:
			sawNew = true
			if decision.Allow {
				t.Fatalf("the new generation returned a mixed/allowed decision")
			}
		default:
			t.Fatalf("a decision came from an unknown generation %q", decision.Generation)
		}
	}
	if !sawOld || !sawNew {
		t.Fatalf("expected decisions from both generations, got old=%v new=%v (total=%d)", sawOld, sawNew, len(collected))
	}

	// The old view is retired once its in-flight requests drained.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		oldView := bundleViewStore.views[owner]
		if oldView != nil && oldView.generation == gen2.Generation {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if view := bundleViewStore.get(owner); view == nil || view.generation != gen2.Generation {
		t.Fatalf("the view store did not settle on the new generation")
	}
}

// TestPolicyBundleAdapterFailureRollback forces an adapter failure inside the
// transaction and proves the live enforcer and adapter stay untouched.
func TestPolicyBundleAdapterFailureRollback(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)
	gen1 := planAndPublish(t, &PolicyBundle{
		Owner:       owner,
		Roles:       []*Role{cloneRole(role)},
		Permissions: []*Permission{clonePermission(permission)},
	})
	rulesBefore := permissionRuleRows(t)

	bundlePublishFailureHook = func() error { return errors.New("simulated adapter failure") }
	defer func() { bundlePublishFailureHook = nil }()

	updatedPermission := clonePermission(permission)
	updatedPermission.Resources = []string{"res2"}
	bundle := &PolicyBundle{
		Owner:       owner,
		Permissions: []*Permission{updatedPermission},
	}
	_, err := PublishPolicyBundle(bundle, "")
	if err == nil || !strings.Contains(err.Error(), "simulated adapter failure") {
		t.Fatalf("the adapter failure was not propagated, got: %v", err)
	}

	// Configuration rows, rule rows, the generation pointer and the live view all stay.
	storedPermission, err := GetPermission(permission.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if len(storedPermission.Resources) != 1 || storedPermission.Resources[0] != "res1" {
		t.Fatalf("the permission row changed despite the rollback: %+v", storedPermission.Resources)
	}
	rulesAfter := permissionRuleRows(t)
	if len(rulesAfter) != len(rulesBefore) {
		t.Fatalf("the rule count changed from %d to %d despite the rollback", len(rulesBefore), len(rulesAfter))
	}
	generations, err := GetPolicyBundleGenerations(owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, generation := range generations {
		if generation.Status != BundleGenerationPublished && generation.Status != BundleGenerationRetired {
			t.Fatalf("an unexpected generation state survived: %+v", generation)
		}
	}
	decision := enforceRequest(t, owner, permission.GetId(),
		util.GetId(owner, "alice"), "res1", "read")
	if decision.Generation != gen1.Generation || !decision.Allow {
		t.Fatalf("the live view changed despite the rollback: %+v", decision)
	}
}

// TestPolicyBundleCrossOwnerRejected reports cross-owner references with exact paths.
func TestPolicyBundleCrossOwner(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)

	foreignRole := cloneRole(role)
	foreignRole.Owner = "other-org"
	_, err := PlanPolicyBundle(&PolicyBundle{
		Owner: owner,
		Roles: []*Role{foreignRole},
	})
	if err == nil || !strings.Contains(err.Error(), "roles[0].owner") {
		t.Fatalf("the cross-owner role was not rejected: %v", err)
	}

	crossRefPermission := clonePermission(permission)
	crossRefPermission.Roles = []string{"other-org/role-x"}
	_, err = PlanPolicyBundle(&PolicyBundle{
		Owner:       owner,
		Permissions: []*Permission{crossRefPermission},
	})
	if err == nil || !strings.Contains(err.Error(), "permissions[0].roles[0]") {
		t.Fatalf("the cross-owner role reference was not rejected: %v", err)
	}
}

// TestPolicyBundleExternalAdapterUnsupported returns the explicit Unsupported error for
// external adapters and never promises a distributed transaction.
func TestPolicyBundleExternalAdapterUnsupported(t *testing.T) {
	setupBundleTestDB(t)
	owner := "org-a"
	seedBundleUser(t, owner, "alice")
	externalAdapter := &Adapter{
		Owner: owner, Name: "external-adapter", UseSameDb: false,
		DatabaseType: "mysql", Table: "external_rule",
	}
	if _, err := ormer.Engine.Insert(externalAdapter); err != nil {
		t.Fatal(err)
	}
	permission := &Permission{
		Owner: owner, Name: "perm-ext", IsEnabled: true, Effect: "allow",
		Adapter:   "external-adapter",
		Users:     []string{util.GetId(owner, "alice")},
		Resources: []string{"res1"},
		Actions:   []string{"read"},
	}
	bundle := &PolicyBundle{Owner: owner, Permissions: []*Permission{permission}}

	plan, err := PlanPolicyBundle(bundle)
	if err == nil {
		t.Fatalf("the external adapter was accepted")
	}
	if !IsPolicyBundleUnsupported(err) {
		t.Fatalf("the error = %v, want ErrPolicyBundleUnsupported", err)
	}
	if plan == nil || plan.Supported {
		t.Fatalf("the plan should report Supported=false")
	}
	if _, err = PublishPolicyBundle(bundle, ""); !IsPolicyBundleUnsupported(err) {
		t.Fatalf("the publish error = %v, want ErrPolicyBundleUnsupported", err)
	}
}

// TestPolicyBundleStaleRevisionRejected proves the pre-commit revision check blocks a
// plan built against an outdated row.
func TestPolicyBundleStaleRevisionRejected(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)
	planAndPublish(t, &PolicyBundle{
		Owner:       owner,
		Roles:       []*Role{cloneRole(role)},
		Permissions: []*Permission{clonePermission(permission)},
	})

	updatedRole := cloneRole(role)
	updatedRole.Users = []string{util.GetId(owner, "bob")}
	bundle := &PolicyBundle{
		Owner:     owner,
		Roles:     []*Role{updatedRole},
		Revisions: map[string]string{role.GetId(): "0123456789abcdef"},
	}
	_, err := PublishPolicyBundle(bundle, "")
	if err == nil || !strings.Contains(err.Error(), "revision mismatch") {
		t.Fatalf("the stale revision was not rejected: %v", err)
	}

	// The row keeps its original state.
	storedRole, err := GetRole(role.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if util.InSlice(storedRole.Users, util.GetId(owner, "bob")) {
		t.Fatalf("the stale bundle modified the role despite the revision mismatch")
	}
}

// TestPolicyBundleSingleItemApiMarksStale keeps the legacy single-item APIs working and
// ensures they advance the invalidated generation.
func TestPolicyBundleSingleItemApiMarksStale(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)
	gen1 := planAndPublish(t, &PolicyBundle{
		Owner:       owner,
		Roles:       []*Role{cloneRole(role)},
		Permissions: []*Permission{clonePermission(permission)},
	})

	extraRole := &Role{Owner: owner, Name: "role-extra", IsEnabled: true}
	affected, err := AddRole(extraRole)
	if err != nil || !affected {
		t.Fatalf("the legacy AddRole API broke: affected=%v err=%v", affected, err)
	}

	status, generation, err := GetPolicyBundlePublishStatus(owner, gen1.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if status != BundleGenerationStale || generation != gen1.Generation {
		t.Fatalf("the generation status = %s, want Stale", status)
	}
	if view := bundleViewStore.get(owner); view != nil {
		t.Fatalf("the stale generation view was not dropped")
	}
}

// TestPolicyBundleWebhookOnlyAfterCommit emits webhook events solely for confirmed
// commits.
func TestPolicyBundleWebhookOnlyAfterCommit(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)

	webhook := &Webhook{
		Owner: "admin", Name: "bundle-hook", Organization: owner,
		Url: "http://127.0.0.1:9/unreachable", Method: "POST", ContentType: "application/json",
		Events:    []string{EventPolicyBundlePublished},
		IsEnabled: true,
	}
	if _, err := ormer.Engine.Insert(webhook); err != nil {
		t.Fatal(err)
	}

	bundle := &PolicyBundle{
		Owner:       owner,
		Roles:       []*Role{cloneRole(role)},
		Permissions: []*Permission{clonePermission(permission)},
	}
	gen1 := planAndPublish(t, bundle)

	eventCount, err := ormer.Engine.Count(&WebhookEvent{})
	if err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("the confirmed commit created %d webhook events, want 1", eventCount)
	}
	event := WebhookEvent{}
	if existed, err := ormer.Engine.Get(&event); err != nil || !existed {
		t.Fatalf("the webhook event was not persisted: %v", err)
	}
	if event.EventType != EventPolicyBundlePublished || !strings.Contains(event.Payload, gen1.Generation) {
		t.Fatalf("the webhook event payload is wrong: %+v", event)
	}

	// A rolled-back publish must not emit anything.
	bundlePublishFailureHook = func() error { return errors.New("boom") }
	defer func() { bundlePublishFailureHook = nil }()
	updatedPermission := clonePermission(permission)
	updatedPermission.Resources = []string{"res9"}
	if _, err = PublishPolicyBundle(&PolicyBundle{Owner: owner, Permissions: []*Permission{updatedPermission}}, ""); err == nil {
		t.Fatalf("the forced failure did not abort the publish")
	}
	eventCount, err = ormer.Engine.Count(&WebhookEvent{})
	if err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("the failed commit emitted a webhook event, count = %d", eventCount)
	}
}

// TestPolicyBundleCycleAndMissingReference covers the remaining static validation paths.
func TestPolicyBundleCycleAndMissingReference(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	seedBundleUser(t, owner, "alice")

	role1 := &Role{Owner: owner, Name: "role-1", IsEnabled: true, Roles: []string{util.GetId(owner, "role-2")}}
	role2 := &Role{Owner: owner, Name: "role-2", IsEnabled: true, Roles: []string{util.GetId(owner, "role-1")}}
	_, err := PlanPolicyBundle(&PolicyBundle{Owner: owner, Roles: []*Role{role1, role2}})
	if err == nil || !strings.Contains(err.Error(), "circular role inheritance") {
		t.Fatalf("the role cycle was not rejected: %v", err)
	}

	missingRole := &Role{Owner: owner, Name: "role-3", IsEnabled: true, Roles: []string{util.GetId(owner, "role-ghost")}}
	_, err = PlanPolicyBundle(&PolicyBundle{Owner: owner, Roles: []*Role{missingRole}})
	if err == nil || !strings.Contains(err.Error(), "missing role") {
		t.Fatalf("the missing role reference was not rejected: %v", err)
	}
}

// TestPolicyBundleGroupSubject exercises the group-based subject path inside the
// isolated candidate enforcer and the published view.
func TestPolicyBundleGroupSubject(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	seedBundleUser(t, owner, "alice", util.GetId(owner, "group-1"))
	group := &Group{Owner: owner, Name: "group-1", IsEnabled: true, IsTopGroup: true}
	if _, err := ormer.Engine.Insert(group); err != nil {
		t.Fatal(err)
	}
	permission := &Permission{
		Owner: owner, Name: "perm-group", IsEnabled: true, Effect: "allow",
		Groups:    []string{util.GetId(owner, "group-1")},
		Resources: []string{"res1"},
		Actions:   []string{"read"},
	}
	seedBundlePermission(t, permission)
	request := []interface{}{util.GetId(owner, "alice"), "res1", "read"}

	gen := planAndPublish(t, &PolicyBundle{
		Owner:       owner,
		Groups:      []*Group{group},
		Permissions: []*Permission{permission},
		RequestCorpus: []PolicyBundleRequest{
			{PermissionId: permission.GetId(), Request: request, ExpectAllow: boolPtr(true)},
		},
	})
	decision := enforceRequest(t, owner, permission.GetId(), request...)
	if !decision.Allow || decision.Generation != gen.Generation {
		t.Fatalf("the group-based permission was not enforced: %+v", decision)
	}

	// A user outside the group is denied by the same view.
	denied := enforceRequest(t, owner, permission.GetId(),
		util.GetId(owner, "bob"), "res1", "read")
	if denied.Allow {
		t.Fatalf("a user outside the group was unexpectedly allowed")
	}
}

// TestPolicyBundleNoImplicitDelete proves objects absent from the bundle survive a
// publish.
func TestPolicyBundleNoImplicitDelete(t *testing.T) {
	setupBundleTestDB(t)
	owner := "built-in"
	role, permission := seedBaselineBundle(t, owner)
	untouchedRole := seedBundleRole(t, &Role{Owner: owner, Name: "role-keep", IsEnabled: true})

	planAndPublish(t, &PolicyBundle{
		Owner:       owner,
		Roles:       []*Role{cloneRole(role)},
		Permissions: []*Permission{clonePermission(permission)},
	})

	kept, err := GetRole(untouchedRole.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if kept == nil {
		t.Fatalf("the bundle implicitly deleted a role it did not list")
	}
	if view := bundleViewStore.get(owner); view == nil {
		t.Fatalf("the published view is missing")
	} else if view.candidate.roleMap[untouchedRole.GetId()] == nil {
		t.Fatalf("the published snapshot dropped the unlisted role %s", untouchedRole.GetId())
	}
}

func TestPolicyBundleErrorPathFormatting(t *testing.T) {
	err := bundleError("permissions[2].model", "bad model: %s", "x")
	if !strings.Contains(err.Error(), "permissions[2].model") {
		t.Fatalf("the formatted error lost its path: %s", err.Error())
	}
	wrapped := fmt.Errorf("wrap: %w", err)
	var target *PolicyBundleError
	if !errors.As(wrapped, &target) {
		t.Fatalf("errors.As did not unwrap the PolicyBundleError")
	}
}
