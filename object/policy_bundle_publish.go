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
	"sync"
	"sync/atomic"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casbin/casbin/v2"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

// bundlePublishFailureHook is a test-only seam. When set, PublishPolicyBundle invokes
// it inside the transaction right before commit; a returned error forces a rollback and
// proves the live enforcer/adapter stay untouched on adapter failure.
var bundlePublishFailureHook func() error

// ---------- generation / state persistence ----------

func GetPolicyBundleGenerations(owner string) ([]*PolicyBundleGeneration, error) {
	generations := []*PolicyBundleGeneration{}
	err := ormer.Engine.Desc("created_time").Find(&generations, &PolicyBundleGeneration{Owner: owner})
	if err != nil {
		return nil, err
	}
	return generations, nil
}

func GetPolicyBundleGeneration(owner string, name string) (*PolicyBundleGeneration, error) {
	if owner == "" || name == "" {
		return nil, nil
	}
	generation := PolicyBundleGeneration{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&generation)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return &generation, nil
}

// GetPolicyBundlePublishStatus answers "did my commit land?" for callers that lost the
// publish response. It never mutates anything, so an uncertain commit is queried before
// the client retries.
func GetPolicyBundlePublishStatus(owner string, generationName string) (status string, generation string, err error) {
	if generationName != "" {
		generationRow, getErr := GetPolicyBundleGeneration(owner, generationName)
		if getErr != nil {
			return "", "", getErr
		}
		if generationRow == nil {
			return "NotFound", generationName, nil
		}
		return generationRow.Status, generationRow.Name, nil
	}

	state, err := getBundleState(owner)
	if err != nil {
		return "", "", err
	}
	if state == nil || state.PublishedGeneration == "" {
		return "NoGeneration", "", nil
	}
	generationRow, err := GetPolicyBundleGeneration(owner, state.PublishedGeneration)
	if err != nil {
		return "", "", err
	}
	if generationRow == nil {
		return "NoGeneration", state.PublishedGeneration, nil
	}
	return generationRow.Status, generationRow.Name, nil
}

func getBundleState(owner string) (*PolicyBundleState, error) {
	state := PolicyBundleState{Owner: owner}
	existed, err := ormer.Engine.Get(&state)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return &state, nil
}

func getBundleStateTx(tx *xorm.Session, owner string) (*PolicyBundleState, error) {
	state := PolicyBundleState{Owner: owner}
	existed, err := tx.Get(&state)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return &state, nil
}

func getGenerationByDigest(owner string, digest string) (*PolicyBundleGeneration, error) {
	if digest == "" {
		return nil, nil
	}
	generation := PolicyBundleGeneration{}
	existed, err := ormer.Engine.Where("owner = ? AND digest = ?", owner, digest).Get(&generation)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return &generation, nil
}

// ---------- publish ----------

// bundlePreImages collects the database rows as they were before the transaction, so the
// policy diff can compare old and new rule sets and revisions can be re-verified.
type bundlePreImages struct {
	roles  map[string]*Role
	groups map[string]*Group
	perms  map[string]*Permission
}

func newBundlePreImages() *bundlePreImages {
	return &bundlePreImages{
		roles:  map[string]*Role{},
		groups: map[string]*Group{},
		perms:  map[string]*Permission{},
	}
}

// PublishPolicyBundle re-runs the full plan outside any transaction, then commits the
// configuration rows, the Casbin rule changes and the generation pointer in one local
// xorm transaction. Readers therefore only ever see the complete old or the complete new
// view. External adapters without an atomic protocol are rejected up front.
func PublishPolicyBundle(bundle *PolicyBundle, plannedDigest string) (*PolicyBundlePublishResult, error) {
	if bundle == nil {
		return nil, bundleError("", "the policy bundle is empty")
	}

	// Short-circuit retries before re-planning: once the exact digest is committed,
	// re-running the (now stale, e.g. renamed) bundle would fail for no good reason.
	if plannedDigest != "" {
		existing, err := getGenerationByDigest(bundle.Owner, plannedDigest)
		if err != nil {
			return nil, err
		}
		if existing != nil && existing.Status == BundleGenerationPublished {
			return publishResultFromGeneration(existing)
		}
	}

	candidate, plan, err := preparePolicyBundle(bundle)
	if err != nil {
		return nil, err
	}
	if !plan.Supported {
		return nil, fmt.Errorf("%w: %s", ErrPolicyBundleUnsupported, plan.UnsupportedReason)
	}
	if plannedDigest != "" && plannedDigest != plan.Digest {
		return nil, bundleError("",
			"the planned digest %s does not match the recomputed digest %s, please re-plan before publishing",
			plannedDigest, plan.Digest)
	}

	// Idempotent retry for callers that did not carry a digest: if the exact view was
	// already committed (the caller lost the response), report the existing generation
	// instead of publishing twice.
	existing, err := getGenerationByDigest(bundle.Owner, plan.Digest)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Status == BundleGenerationPublished {
		return publishResultFromGeneration(existing)
	}

	session := ormer.Engine.NewSession()
	defer session.Close()

	if err = session.Begin(); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = session.Rollback()
		}
	}()

	preImages, err := reVerifyBundlePreStateTx(session, bundle, candidate)
	if err != nil {
		return nil, err
	}

	if err = applyBundleRowsTx(session, bundle, candidate); err != nil {
		return nil, err
	}

	if err = applyBundlePolicyRulesTx(session, preImages, bundle, candidate); err != nil {
		return nil, err
	}

	// The failure hook runs while the transaction is still open; any error rolls
	// everything back, including the rule-table changes.
	if bundlePublishFailureHook != nil {
		if err = bundlePublishFailureHook(); err != nil {
			return nil, fmt.Errorf("policy bundle publish aborted by adapter failure hook: %w", err)
		}
	}

	generation, err := writeBundleGenerationTx(session, bundle, candidate, plan)
	if err != nil {
		return nil, err
	}

	if err = session.Commit(); err != nil {
		return nil, err
	}
	committed = true

	// Everything below runs after the confirmed commit. The in-memory view swap takes
	// no database lock, so arbitrary custom matcher functions never execute while a DB
	// transaction is held open.
	installBundleView(bundle.Owner, generation.Name, plan.Snapshot)
	fireBundlePublishedWebhooks(bundle.Owner, generation)

	return &PolicyBundlePublishResult{
		Owner:            generation.Owner,
		Generation:       generation.Name,
		ParentGeneration: generation.ParentGeneration,
		Digest:           generation.Digest,
		Status:           generation.Status,
		Snapshot:         plan.Snapshot,
		Objects:          plan.Objects,
	}, nil
}

func publishResultFromGeneration(generation *PolicyBundleGeneration) (*PolicyBundlePublishResult, error) {
	snapshot := PolicyBundleSnapshot{}
	if generation.Snapshot != "" {
		if err := json.Unmarshal([]byte(generation.Snapshot), &snapshot); err != nil {
			return nil, err
		}
	}
	objects := []PolicyBundleObjectRef{}
	if generation.Objects != "" {
		if err := json.Unmarshal([]byte(generation.Objects), &objects); err != nil {
			return nil, err
		}
	}
	return &PolicyBundlePublishResult{
		Owner:            generation.Owner,
		Generation:       generation.Name,
		ParentGeneration: generation.ParentGeneration,
		Digest:           generation.Digest,
		Status:           generation.Status,
		Snapshot:         &snapshot,
		Objects:          objects,
	}, nil
}

// reVerifyBundlePreStateTx reloads every touched row inside the transaction and checks
// the revisions the plan was built against. This is the last line of defense against a
// concurrent writer that moved between plan and publish.
func reVerifyBundlePreStateTx(tx *xorm.Session, bundle *PolicyBundle, candidate *bundleCandidate) (*bundlePreImages, error) {
	preImages := newBundlePreImages()

	verifyRevision := func(path string, id string, current interface{}) error {
		expected, ok := bundle.Revisions[id]
		if !ok || expected == "" {
			return nil
		}
		if bundleRevision(current) != expected {
			return bundleError(path,
				"the row %q changed after the plan was built (revision mismatch), please re-plan before publishing", id)
		}
		return nil
	}

	for i, rename := range bundle.Renames {
		path := fmt.Sprintf("renames[%d]", i)
		switch rename.Kind {
		case "role":
			owner, name, err := util.GetOwnerAndNameFromIdWithError(rename.OldId)
			if err != nil {
				return nil, bundleError(path, "%w", err)
			}
			role := Role{Owner: owner, Name: name}
			existed, err := tx.Get(&role)
			if err != nil {
				return nil, err
			}
			if !existed {
				return nil, bundleError(path, "the role %q to rename no longer exists", rename.OldId)
			}
			if err = verifyRevision(path, rename.OldId, &role); err != nil {
				return nil, err
			}
			preImages.roles[rename.OldId] = &role
		case "group":
			owner, name, err := util.GetOwnerAndNameFromIdWithError(rename.OldId)
			if err != nil {
				return nil, bundleError(path, "%w", err)
			}
			group := Group{Owner: owner, Name: name}
			existed, err := tx.Get(&group)
			if err != nil {
				return nil, err
			}
			if !existed {
				return nil, bundleError(path, "the group %q to rename no longer exists", rename.OldId)
			}
			if err = verifyRevision(path, rename.OldId, &group); err != nil {
				return nil, err
			}
			preImages.groups[rename.OldId] = &group
		case "permission":
			owner, name, err := util.GetOwnerAndNameFromIdWithError(rename.OldId)
			if err != nil {
				return nil, bundleError(path, "%w", err)
			}
			permission := Permission{Owner: owner, Name: name}
			existed, err := tx.Get(&permission)
			if err != nil {
				return nil, err
			}
			if !existed {
				return nil, bundleError(path, "the permission %q to rename no longer exists", rename.OldId)
			}
			if err = verifyRevision(path, rename.OldId, &permission); err != nil {
				return nil, err
			}
			preImages.perms[rename.OldId] = &permission
		default:
			return nil, bundleError(path, "unknown rename kind %q", rename.Kind)
		}
	}

	for i, role := range bundle.Roles {
		path := fmt.Sprintf("roles[%d]", i)
		current := Role{Owner: role.Owner, Name: role.Name}
		existed, err := tx.Get(&current)
		if err != nil {
			return nil, err
		}
		if !existed && bundle.Revisions[role.GetId()] != "" {
			return nil, bundleError(path, "the role %q no longer exists", role.GetId())
		}
		if existed {
			if err = verifyRevision(path, role.GetId(), &current); err != nil {
				return nil, err
			}
			preImages.roles[role.GetId()] = &current
		}
	}

	for i, group := range bundle.Groups {
		path := fmt.Sprintf("groups[%d]", i)
		current := Group{Owner: group.Owner, Name: group.Name}
		existed, err := tx.Get(&current)
		if err != nil {
			return nil, err
		}
		if !existed && bundle.Revisions[group.GetId()] != "" {
			return nil, bundleError(path, "the group %q no longer exists", group.GetId())
		}
		if existed {
			if err = verifyRevision(path, group.GetId(), &current); err != nil {
				return nil, err
			}
			preImages.groups[group.GetId()] = &current
		}
	}

	for i, permission := range bundle.Permissions {
		path := fmt.Sprintf("permissions[%d]", i)
		current := Permission{Owner: permission.Owner, Name: permission.Name}
		existed, err := tx.Get(&current)
		if err != nil {
			return nil, err
		}
		if !existed && bundle.Revisions[permission.GetId()] != "" {
			return nil, bundleError(path, "the permission %q no longer exists", permission.GetId())
		}
		if existed {
			if err = verifyRevision(path, permission.GetId(), &current); err != nil {
				return nil, err
			}
			preImages.perms[permission.GetId()] = &current
		}
	}

	// Rename-driven reference rewrites also need their pre-images, otherwise the policy
	// diff would treat every unchanged rule as a new insertion.
	for _, id := range sortedRoleIds(candidate.rewrittenRoles) {
		owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
		if err != nil {
			return nil, err
		}
		role := Role{Owner: owner, Name: name}
		existed, err := tx.Get(&role)
		if err != nil {
			return nil, err
		}
		if existed {
			preImages.roles[id] = &role
		}
	}
	for _, id := range sortedPermIds(candidate.rewrittenPerms) {
		owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
		if err != nil {
			return nil, err
		}
		permission := Permission{Owner: owner, Name: name}
		existed, err := tx.Get(&permission)
		if err != nil {
			return nil, err
		}
		if existed {
			preImages.perms[id] = &permission
		}
	}

	return preImages, nil
}

// applyBundleRowsTx writes the explicit rows and the rename-driven reference rewrites.
// Rows that are not part of the bundle are only touched when a rename requires it; they
// are never deleted.
func applyBundleRowsTx(tx *xorm.Session, bundle *PolicyBundle, candidate *bundleCandidate) error {
	for _, rename := range bundle.Renames {
		oldOwner, oldName, err := util.GetOwnerAndNameFromIdWithError(rename.OldId)
		if err != nil {
			return err
		}
		switch rename.Kind {
		case "role":
			if _, err = tx.ID(core.PK{oldOwner, oldName}).Delete(&Role{}); err != nil {
				return err
			}
			newRole := candidate.roleMap[rename.NewId]
			if newRole == nil {
				return bundleError("", "the renamed role %q is missing from the candidate snapshot", rename.NewId)
			}
			if _, err = tx.Insert(cloneRole(newRole)); err != nil {
				return err
			}
		case "group":
			if _, err = tx.ID(core.PK{oldOwner, oldName}).Delete(&Group{}); err != nil {
				return err
			}
			newGroup := candidate.groupMap[rename.NewId]
			if newGroup == nil {
				return bundleError("", "the renamed group %q is missing from the candidate snapshot", rename.NewId)
			}
			if _, err = tx.Insert(cloneGroup(newGroup)); err != nil {
				return err
			}
		case "permission":
			if _, err = tx.ID(core.PK{oldOwner, oldName}).Delete(&Permission{}); err != nil {
				return err
			}
			newPermission := candidate.permMap[rename.NewId]
			if newPermission == nil {
				return bundleError("", "the renamed permission %q is missing from the candidate snapshot", rename.NewId)
			}
			if _, err = tx.Insert(clonePermission(newPermission)); err != nil {
				return err
			}
		}
	}

	for _, id := range sortedRoleIds(candidate.explicitRoles) {
		role := candidate.explicitRoles[id]
		affected, err := tx.ID(core.PK{role.Owner, role.Name}).AllCols().Update(role)
		if err != nil {
			return err
		}
		if affected == 0 {
			if _, err = tx.Insert(cloneRole(role)); err != nil {
				return err
			}
		}
	}
	for _, id := range sortedGroupIds(candidate.explicitGroups) {
		group := candidate.explicitGroups[id]
		affected, err := tx.ID(core.PK{group.Owner, group.Name}).AllCols().Update(group)
		if err != nil {
			return err
		}
		if affected == 0 {
			if _, err = tx.Insert(cloneGroup(group)); err != nil {
				return err
			}
		}
	}
	for _, id := range sortedPermIds(candidate.explicitPerms) {
		permission := candidate.explicitPerms[id]
		affected, err := tx.ID(core.PK{permission.Owner, permission.Name}).AllCols().Update(permission)
		if err != nil {
			return err
		}
		if affected == 0 {
			if _, err = tx.Insert(clonePermission(permission)); err != nil {
				return err
			}
		}
	}

	// Persist reference rewrites on rows that stayed outside the explicit set.
	for _, id := range sortedRoleIds(candidate.rewrittenRoles) {
		role := candidate.rewrittenRoles[id]
		if _, err := tx.ID(core.PK{role.Owner, role.Name}).AllCols().Update(role); err != nil {
			return err
		}
	}
	for _, id := range sortedPermIds(candidate.rewrittenPerms) {
		permission := candidate.rewrittenPerms[id]
		if _, err := tx.ID(core.PK{permission.Owner, permission.Name}).AllCols().Update(permission); err != nil {
			return err
		}
	}

	return nil
}

// applyBundlePolicyRulesTx rewrites the Casbin p rules of every affected permission in
// the same transaction as the configuration rows. Only the diff between old and new rule
// sets is deleted/inserted, and the two sides can target different adapter tables when
// a permission moves adapters.
func applyBundlePolicyRulesTx(tx *xorm.Session, preImages *bundlePreImages, bundle *PolicyBundle, candidate *bundleCandidate) error {
	affected := map[string]struct{}{}
	for id := range candidate.explicitPerms {
		affected[id] = struct{}{}
	}
	for id := range candidate.rewrittenPerms {
		affected[id] = struct{}{}
	}
	for _, rename := range bundle.Renames {
		if rename.Kind == "permission" {
			affected[rename.NewId] = struct{}{}
		}
	}

	// Map the new permission id back to its pre-image id so renames can diff correctly.
	preImageId := map[string]string{}
	for _, rename := range bundle.Renames {
		preImageId[rename.NewId] = rename.OldId
	}

	for id := range affected {
		newPermission := candidate.permMap[id]
		if newPermission == nil {
			continue
		}
		oldId := preImageId[id]
		if oldId == "" {
			oldId = id
		}
		oldPermission := preImages.perms[oldId]

		var oldPolicies [][]string
		oldTable := ""
		if oldPermission != nil {
			oldPolicies = getPolicies(oldPermission)
			oldTable = permissionRuleTableName(oldPermission)
		}
		newPolicies := getPolicies(newPermission)
		newTable := permissionRuleTableName(newPermission)

		removedPolicies, addedPolicies := getPoliciesDiff(oldPolicies, newPolicies)

		if oldTable != "" && oldTable != newTable {
			if err := txDeleteCasbinRules(tx, oldTable, removedPolicies); err != nil {
				return err
			}
			if err := txInsertCasbinRules(tx, newTable, addedPolicies); err != nil {
				return err
			}
			continue
		}

		if len(removedPolicies) != 0 {
			if err := txDeleteCasbinRules(tx, newTable, removedPolicies); err != nil {
				return err
			}
		}
		if len(addedPolicies) != 0 {
			if err := txInsertCasbinRules(tx, newTable, addedPolicies); err != nil {
				return err
			}
		}
	}

	return nil
}

func permissionRuleTableName(permission *Permission) string {
	tableName := "permission_rule"
	if permission.Adapter != "" {
		adapter, err := getAdapter(permission.Owner, permission.Adapter)
		if err == nil && adapter != nil && adapter.Table != "" {
			tableName = adapter.Table
		}
	}
	return conf.GetConfigString("tableNamePrefix") + tableName
}

func buildTxCasbinRule(rule []string) *xormadapter.CasbinRule {
	line := xormadapter.CasbinRule{Ptype: "p"}
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}
	return &line
}

func txDeleteCasbinRules(tx *xorm.Session, table string, rules [][]string) error {
	for _, rule := range rules {
		line := buildTxCasbinRule(rule)
		_, err := tx.Table(table).
			MustCols("ptype", "v0", "v1", "v2", "v3", "v4", "v5").
			Delete(line)
		if err != nil {
			return err
		}
	}
	return nil
}

func txInsertCasbinRules(tx *xorm.Session, table string, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}
	lines := make([]*xormadapter.CasbinRule, 0, len(rules))
	for _, rule := range rules {
		lines = append(lines, buildTxCasbinRule(rule))
	}
	_, err := tx.Table(table).Insert(&lines)
	return err
}

// writeBundleGenerationTx persists the new generation, retires the previous one and
// advances the per-organization pointer, all on the same transaction/session.
func writeBundleGenerationTx(tx *xorm.Session, bundle *PolicyBundle, candidate *bundleCandidate, plan *PolicyBundlePlanResult) (*PolicyBundleGeneration, error) {
	state, err := getBundleStateTx(tx, bundle.Owner)
	if err != nil {
		return nil, err
	}
	parentGeneration := ""
	if state != nil {
		parentGeneration = state.PublishedGeneration
		if parentGeneration != "" {
			_, err = tx.ID(core.PK{bundle.Owner, parentGeneration}).
				Cols("status").
				Update(&PolicyBundleGeneration{Status: BundleGenerationRetired})
			if err != nil {
				return nil, err
			}
		}
	}

	snapshotJSON, err := json.Marshal(plan.Snapshot)
	if err != nil {
		return nil, err
	}
	objectsJSON, err := json.Marshal(plan.Objects)
	if err != nil {
		return nil, err
	}

	now := util.GetCurrentTime()
	generation := &PolicyBundleGeneration{
		Owner:              bundle.Owner,
		Name:               "gen-" + util.GenerateId(),
		CreatedTime:        now,
		PublishedTime:      now,
		Status:             BundleGenerationPublished,
		Digest:             plan.Digest,
		ModelAdapterDigest: candidate.modelAdapterDigest,
		ParentGeneration:   parentGeneration,
		Objects:            string(objectsJSON),
		Snapshot:           string(snapshotJSON),
	}
	if _, err = tx.Insert(generation); err != nil {
		return nil, err
	}

	newState := &PolicyBundleState{
		Owner:               bundle.Owner,
		PublishedGeneration: generation.Name,
		Digest:              plan.Digest,
		UpdatedTime:         now,
	}
	if state == nil {
		if _, err = tx.Insert(newState); err != nil {
			return nil, err
		}
	} else {
		if _, err = tx.ID(core.PK{bundle.Owner}).AllCols().Update(newState); err != nil {
			return nil, err
		}
	}

	return generation, nil
}

// ---------- published view store ----------

// policyBundleView is one immutable generation kept in memory for serving authorization
// requests. Enforcement runs entirely on its in-memory enforcers, so no database lock is
// ever held while custom matcher functions execute.
type policyBundleView struct {
	owner      string
	generation string
	snapshot   *PolicyBundleSnapshot

	mu        sync.Mutex
	enforcers map[string]*casbin.Enforcer
	candidate *bundleCandidate

	wg      sync.WaitGroup
	retired atomic.Bool
}

func (v *policyBundleView) enforcerFor(permission *Permission) (*casbin.Enforcer, error) {
	key := permission.GetModelAndAdapter()
	v.mu.Lock()
	defer v.mu.Unlock()

	if enforcer, ok := v.enforcers[key]; ok {
		return enforcer, nil
	}
	enforcer, err := v.candidate.buildEnforcer(permission, nil)
	if err != nil {
		return nil, err
	}
	v.enforcers[key] = enforcer
	return enforcer, nil
}

// retireWhenDrained waits for the in-flight requests of an old generation to finish and
// only then releases its enforcers. New requests are routed to the new view before this
// runs, so the wait is bounded by already accepted requests.
func (v *policyBundleView) retireWhenDrained() {
	v.wg.Wait()
	v.retired.Store(true)
	v.mu.Lock()
	v.enforcers = nil
	v.mu.Unlock()
}

type policyBundleViewManager struct {
	mu    sync.RWMutex
	views map[string]*policyBundleView
}

var bundleViewStore = &policyBundleViewManager{views: map[string]*policyBundleView{}}

func newSnapshotCandidate(snapshot *PolicyBundleSnapshot) *bundleCandidate {
	candidate := &bundleCandidate{
		owner:              snapshot.Owner,
		roleMap:            map[string]*Role{},
		groupMap:           map[string]*Group{},
		permMap:            map[string]*Permission{},
		explicitRoles:      map[string]*Role{},
		explicitGroups:     map[string]*Group{},
		explicitPerms:      map[string]*Permission{},
		explicitRoleIndex:  map[string]int{},
		explicitGroupIndex: map[string]int{},
		explicitPermIndex:  map[string]int{},
		rewrittenRoles:     map[string]*Role{},
		rewrittenPerms:     map[string]*Permission{},
	}
	for _, role := range snapshot.Roles {
		candidate.roleMap[role.GetId()] = cloneRole(role)
	}
	for _, group := range snapshot.Groups {
		candidate.groupMap[group.GetId()] = cloneGroup(group)
	}
	for _, permission := range snapshot.Permissions {
		candidate.permMap[permission.GetId()] = clonePermission(permission)
	}
	return candidate
}

func installBundleView(owner string, generation string, snapshot *PolicyBundleSnapshot) *policyBundleView {
	view := &policyBundleView{
		owner:      owner,
		generation: generation,
		snapshot:   snapshot,
		enforcers:  map[string]*casbin.Enforcer{},
		candidate:  newSnapshotCandidate(snapshot),
	}

	bundleViewStore.mu.Lock()
	oldView := bundleViewStore.views[owner]
	bundleViewStore.views[owner] = view
	bundleViewStore.mu.Unlock()

	if oldView != nil {
		go oldView.retireWhenDrained()
	}
	return view
}

func (m *policyBundleViewManager) get(owner string) *policyBundleView {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.views[owner]
}

func (m *policyBundleViewManager) drop(owner string) *policyBundleView {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldView := m.views[owner]
	delete(m.views, owner)
	return oldView
}

// BundleViewDecision is the authorization decision of one published generation.
type BundleViewDecision struct {
	Allow      bool   `json:"allow"`
	Generation string `json:"generation"`
}

// EnforceWithBundleView serves a request from exactly one published generation view.
// It returns nil decision when no view is installed (the caller can fall back to the
// live enforcer), and never mixes rows of different generations.
func EnforceWithBundleView(owner string, permissionId string, request []interface{}) (*BundleViewDecision, error) {
	view := bundleViewStore.get(owner)
	if view == nil {
		return nil, nil
	}

	view.wg.Add(1)
	defer view.wg.Done()
	if view.retired.Load() {
		return nil, nil
	}

	permission := view.candidate.permMap[permissionId]
	if permission == nil {
		return nil, bundleError("", "the permission %q is not part of the published generation %q", permissionId, view.generation)
	}

	enforcer, err := view.enforcerFor(permission)
	if err != nil {
		return nil, err
	}

	interfaceRequest := util.InterfaceToEnforceArray(request)
	allowed, err := enforcer.Enforce(interfaceRequest...)
	if err != nil {
		return nil, err
	}
	return &BundleViewDecision{Allow: allowed, Generation: view.generation}, nil
}

// NotifyBundleConfigChanged is called by the legacy single-item write APIs. Their
// commits stay fully compatible, but any published generation that described the
// previous state is marked stale and its view is retired so readers cannot get decisions
// from a superseded configuration.
func NotifyBundleConfigChanged(owner string) error {
	if ormer == nil || owner == "" {
		return nil
	}

	state, err := getBundleState(owner)
	if err != nil {
		return err
	}
	if state == nil || state.PublishedGeneration == "" {
		return nil
	}

	_, err = ormer.Engine.ID(core.PK{owner, state.PublishedGeneration}).
		Cols("status").
		Update(&PolicyBundleGeneration{Status: BundleGenerationStale})
	if err != nil {
		return err
	}

	oldView := bundleViewStore.drop(owner)
	if oldView != nil {
		go oldView.retireWhenDrained()
	}
	return nil
}

// ---------- webhooks ----------

// fireBundlePublishedWebhooks creates delivery events only after the transaction has
// been confirmed. A failed or rolled-back publish never emits an event.
func fireBundlePublishedWebhooks(owner string, generation *PolicyBundleGeneration) {
	webhooks := []*Webhook{}
	err := ormer.Engine.Find(&webhooks, &Webhook{Organization: owner})
	if err != nil {
		logs.Warn("policy bundle: failed to load webhooks for organization %s: %s", owner, err.Error())
		return
	}

	payload, err := json.Marshal(struct {
		Generation string                  `json:"generation"`
		Owner      string                  `json:"owner"`
		Digest     string                  `json:"digest"`
		Objects    []PolicyBundleObjectRef `json:"objects"`
	}{
		Generation: generation.Name,
		Owner:      owner,
		Digest:     generation.Digest,
		Objects:    planObjectsFromGeneration(generation),
	})
	if err != nil {
		logs.Warn("policy bundle: failed to marshal the webhook payload: %s", err.Error())
		return
	}

	record := &Record{
		Owner:        "admin",
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: owner,
		Method:       "POLICY_BUNDLE",
		Action:       EventPolicyBundlePublished,
		Object:       string(payload),
		StatusCode:   200,
	}

	for _, webhook := range webhooks {
		if !webhook.IsEnabled || !util.InSlice(webhook.Events, EventPolicyBundlePublished) {
			continue
		}
		if _, err = CreateWebhookEventFromRecord(webhook, record, nil); err != nil {
			logs.Warn("policy bundle: failed to create the webhook event for %s: %s", webhook.GetId(), err.Error())
		}
	}
}

func planObjectsFromGeneration(generation *PolicyBundleGeneration) []PolicyBundleObjectRef {
	objects := []PolicyBundleObjectRef{}
	if generation.Objects == "" {
		return objects
	}
	if err := json.Unmarshal([]byte(generation.Objects), &objects); err != nil {
		return []PolicyBundleObjectRef{}
	}
	return objects
}

// IsPolicyBundleUnsupported lets callers distinguish the explicit unsupported-adapter
// rejection from ordinary validation failures.
func IsPolicyBundleUnsupported(err error) bool {
	return errors.Is(err, ErrPolicyBundleUnsupported)
}
