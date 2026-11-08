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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinlog "github.com/casbin/casbin/v2/log"
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/casdoor/casdoor/util"
)

// PolicyBundle generation lifecycle states.
const (
	BundleGenerationCandidate = "Candidate"
	BundleGenerationPublished = "Published"
	BundleGenerationRetired   = "Retired"
	BundleGenerationStale     = "Stale"
	BundleGenerationFailed    = "Failed"
)

// EventPolicyBundlePublished is the webhook event emitted only after a bundle commit
// has been confirmed by the database transaction.
const EventPolicyBundlePublished = "policy-bundle-published"

// ErrPolicyBundleUnsupported is returned when the bundle targets an external policy
// adapter that does not expose an atomic publish protocol. Casdoor must not pretend a
// distributed transaction exists across independent storages.
var ErrPolicyBundleUnsupported = errors.New("policy bundle: atomic publish is unsupported by the configured external policy adapter")

// PolicyBundleError carries the exact JSON path of the invalid bundle entry, so callers
// know which role, group or permission broke the plan before anything is written.
type PolicyBundleError struct {
	Path string
	Err  error
}

func (e *PolicyBundleError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("policy bundle: %s", e.Err.Error())
	}
	return fmt.Sprintf("policy bundle[%s]: %s", e.Path, e.Err.Error())
}

func (e *PolicyBundleError) Unwrap() error {
	return e.Err
}

func bundleError(path string, format string, args ...interface{}) *PolicyBundleError {
	return &PolicyBundleError{Path: path, Err: fmt.Errorf(format, args...)}
}

// PolicyBundleRename describes an in-bundle rename. The kind discriminates whether the
// old id points at a role, a group or a permission, because ids alone are ambiguous.
type PolicyBundleRename struct {
	Kind  string `json:"kind"`
	OldId string `json:"oldId"`
	NewId string `json:"newId"`
}

// PolicyBundle is the explicit, finite object set of a planned authorization change.
// Only the listed roles, groups and permissions may change; everything else in the
// organization keeps its current state and is never deleted automatically.
type PolicyBundle struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`

	Roles       []*Role       `json:"roles"`
	Groups      []*Group      `json:"groups"`
	Permissions []*Permission `json:"permissions"`

	// Renames records old-id to new-id moves. All references inside the candidate
	// snapshot are rewritten consistently, so a role rename stays in sync with the
	// permissions that grant it.
	Renames []PolicyBundleRename `json:"renames,omitempty"`

	// Revisions binds every touched object (keyed by its current id, the old id for
	// renames) to the revision the caller read. A mismatch at publish time aborts the
	// whole bundle, because another writer moved the row in the meantime.
	Revisions map[string]string `json:"revisions,omitempty"`

	// RequestCorpus is the finite regression set executed against the isolated
	// candidate enforcers. JSON being parseable is not enough: the policies have to
	// produce the expected authorization decisions.
	RequestCorpus []PolicyBundleRequest `json:"requestCorpus,omitempty"`
}

// PolicyBundleRequest is one regression request. ExpectAllow, when set, turns the entry
// into an assertion.
type PolicyBundleRequest struct {
	PermissionId string        `json:"permissionId,omitempty"`
	Request      []interface{} `json:"request"`
	ExpectAllow  *bool         `json:"expectAllow,omitempty"`
}

// PolicyBundleObjectRef records the revision of one original row covered by the bundle.
type PolicyBundleObjectRef struct {
	Kind     string `json:"kind"`
	Id       string `json:"id"`
	Revision string `json:"revision"`
	Action   string `json:"action"`
}

// PolicyBundleSnapshot is the complete candidate configuration of one organization:
// the live rows overlaid with the explicit bundle changes. Enforcement reads a single
// snapshot, it never splices a new role together with an old permission.
type PolicyBundleSnapshot struct {
	Owner       string        `json:"owner"`
	Roles       []*Role       `json:"roles"`
	Groups      []*Group      `json:"groups"`
	Permissions []*Permission `json:"permissions"`
}

// PolicyBundleGeneration is one immutable published (or failed) generation. The row is
// written inside the same database transaction as the configuration and policy rows, so
// a generation only exists once the whole view is committed.
type PolicyBundleGeneration struct {
	Owner         string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name          string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime   string `xorm:"varchar(100)" json:"createdTime"`
	PublishedTime string `xorm:"varchar(100)" json:"publishedTime"`

	Status string `xorm:"varchar(50) index" json:"status"`

	// Digest covers the object revisions, the model/adapter digest and the full
	// candidate snapshot, so publish can prove it commits the exact planned view.
	Digest             string `xorm:"varchar(128)" json:"digest"`
	ModelAdapterDigest string `xorm:"varchar(128)" json:"modelAdapterDigest"`
	ParentGeneration   string `xorm:"varchar(100)" json:"parentGeneration"`

	Objects  string `xorm:"mediumtext" json:"objects"`
	Snapshot string `xorm:"mediumtext" json:"snapshot"`

	// Error is populated for failed generations and stays empty for published ones.
	Error string `xorm:"mediumtext" json:"error,omitempty"`
}

// PolicyBundleState is the single per-organization pointer to the candidate / published
// generation. Advancing it together with the configuration inside one transaction is
// what gives readers an all-old or all-new view.
type PolicyBundleState struct {
	Owner               string `xorm:"varchar(100) notnull pk" json:"owner"`
	PublishedGeneration string `xorm:"varchar(100)" json:"publishedGeneration"`
	CandidateGeneration string `xorm:"varchar(100)" json:"candidateGeneration"`
	Digest              string `xorm:"varchar(128)" json:"digest"`
	UpdatedTime         string `xorm:"varchar(100)" json:"updatedTime"`
}

func (g *PolicyBundleGeneration) GetId() string {
	return util.GetId(g.Owner, g.Name)
}

// PolicyBundleRequestDecision records the decision of the isolated candidate enforcer
// and, when available, the decision of the independent live enforcer for the same
// request, so the two can be compared per request.
type PolicyBundleRequestDecision struct {
	Index           int           `json:"index"`
	PermissionId    string        `json:"permissionId"`
	Request         []interface{} `json:"request"`
	CandidateAllow  bool          `json:"candidateAllow"`
	LiveAllow       bool          `json:"liveAllow"`
	HasLiveDecision bool          `json:"hasLiveDecision"`
	ExpectAllow     *bool         `json:"expectAllow,omitempty"`
	Matched         bool          `json:"matched"`
	Error           string        `json:"error,omitempty"`
}

// PolicyBundlePlanResult is the output of the write-free planning phase.
type PolicyBundlePlanResult struct {
	Owner              string                        `json:"owner"`
	Digest             string                        `json:"digest"`
	ModelAdapterDigest string                        `json:"modelAdapterDigest"`
	Objects            []PolicyBundleObjectRef       `json:"objects"`
	Snapshot           *PolicyBundleSnapshot         `json:"snapshot"`
	Decisions          []PolicyBundleRequestDecision `json:"decisions"`

	// Supported is false when an external adapter cannot offer atomic publish.
	Supported         bool   `json:"supported"`
	UnsupportedReason string `json:"unsupportedReason,omitempty"`
}

// PolicyBundlePublishResult is returned after a confirmed commit.
type PolicyBundlePublishResult struct {
	Owner            string                  `json:"owner"`
	Generation       string                  `json:"generation"`
	ParentGeneration string                  `json:"parentGeneration"`
	Digest           string                  `json:"digest"`
	Status           string                  `json:"status"`
	Snapshot         *PolicyBundleSnapshot   `json:"snapshot"`
	Objects          []PolicyBundleObjectRef `json:"objects"`
}

func bundleRevision(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func digestJSON(value interface{}) string {
	return bundleRevision(value)
}

func cloneRole(role *Role) *Role {
	clone := *role
	clone.Users = append([]string{}, role.Users...)
	clone.Groups = append([]string{}, role.Groups...)
	clone.Roles = append([]string{}, role.Roles...)
	clone.Domains = append([]string{}, role.Domains...)
	return &clone
}

func cloneGroup(group *Group) *Group {
	clone := *group
	return &clone
}

func clonePermission(permission *Permission) *Permission {
	clone := *permission
	clone.Users = append([]string{}, permission.Users...)
	clone.Groups = append([]string{}, permission.Groups...)
	clone.Roles = append([]string{}, permission.Roles...)
	clone.Domains = append([]string{}, permission.Domains...)
	clone.Resources = append([]string{}, permission.Resources...)
	clone.Actions = append([]string{}, permission.Actions...)
	return &clone
}

// bundleCandidate holds the merged in-memory configuration used for validation and for
// building isolated enforcers. Nothing in here touches the database until publish.
type bundleCandidate struct {
	owner string

	roleMap  map[string]*Role
	groupMap map[string]*Group
	permMap  map[string]*Permission

	explicitRoles  map[string]*Role
	explicitGroups map[string]*Group
	explicitPerms  map[string]*Permission

	explicitRoleIndex  map[string]int
	explicitGroupIndex map[string]int
	explicitPermIndex  map[string]int

	// rewrittenRows stores live rows that are not in the explicit set but had to be
	// updated because a rename moved a reference they point at.
	rewrittenRoles map[string]*Role
	rewrittenPerms map[string]*Permission

	refs []PolicyBundleObjectRef

	modelAdapterDigest string
	unsupportedReason  string
}

func sortedRoleIds(m map[string]*Role) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortedGroupIds(m map[string]*Group) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortedPermIds(m map[string]*Permission) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (c *bundleCandidate) snapshot() *PolicyBundleSnapshot {
	roles := make([]*Role, 0, len(c.roleMap))
	for _, id := range sortedRoleIds(c.roleMap) {
		roles = append(roles, cloneRole(c.roleMap[id]))
	}
	groups := make([]*Group, 0, len(c.groupMap))
	for _, id := range sortedGroupIds(c.groupMap) {
		groups = append(groups, cloneGroup(c.groupMap[id]))
	}
	perms := make([]*Permission, 0, len(c.permMap))
	for _, id := range sortedPermIds(c.permMap) {
		perms = append(perms, clonePermission(c.permMap[id]))
	}
	return &PolicyBundleSnapshot{Owner: c.owner, Roles: roles, Groups: groups, Permissions: perms}
}

// buildBundleCandidate loads the live rows and overlays the explicit bundle changes in
// memory. It performs no writes.
func buildBundleCandidate(bundle *PolicyBundle) (*bundleCandidate, error) {
	if bundle == nil {
		return nil, bundleError("", "the policy bundle is empty")
	}
	if bundle.Owner == "" {
		return nil, bundleError("", "the policy bundle owner is required")
	}

	for i, role := range bundle.Roles {
		if role == nil {
			return nil, bundleError(fmt.Sprintf("roles[%d]", i), "the role is null")
		}
		if role.Owner != bundle.Owner {
			return nil, bundleError(fmt.Sprintf("roles[%d].owner", i),
				"the role owner %q does not match the bundle owner %q: cross-owner changes are not allowed", role.Owner, bundle.Owner)
		}
	}
	for i, group := range bundle.Groups {
		if group == nil {
			return nil, bundleError(fmt.Sprintf("groups[%d]", i), "the group is null")
		}
		if group.Owner != bundle.Owner {
			return nil, bundleError(fmt.Sprintf("groups[%d].owner", i),
				"the group owner %q does not match the bundle owner %q: cross-owner changes are not allowed", group.Owner, bundle.Owner)
		}
	}
	for i, permission := range bundle.Permissions {
		if permission == nil {
			return nil, bundleError(fmt.Sprintf("permissions[%d]", i), "the permission is null")
		}
		if permission.Owner != bundle.Owner {
			return nil, bundleError(fmt.Sprintf("permissions[%d].owner", i),
				"the permission owner %q does not match the bundle owner %q: cross-owner changes are not allowed", permission.Owner, bundle.Owner)
		}
	}

	liveRoles, err := GetRoles(bundle.Owner)
	if err != nil {
		return nil, err
	}
	liveGroups, err := GetGroups(bundle.Owner)
	if err != nil {
		return nil, err
	}
	livePerms, err := GetPermissions(bundle.Owner)
	if err != nil {
		return nil, err
	}

	candidate := &bundleCandidate{
		owner:              bundle.Owner,
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

	liveRoleRevision := map[string]string{}
	for _, role := range liveRoles {
		candidate.roleMap[role.GetId()] = cloneRole(role)
		liveRoleRevision[role.GetId()] = bundleRevision(role)
	}
	liveGroupRevision := map[string]string{}
	for _, group := range liveGroups {
		candidate.groupMap[group.GetId()] = cloneGroup(group)
		liveGroupRevision[group.GetId()] = bundleRevision(group)
	}
	livePermRevision := map[string]string{}
	for _, permission := range livePerms {
		candidate.permMap[permission.GetId()] = clonePermission(permission)
		livePermRevision[permission.GetId()] = bundleRevision(permission)
	}

	// Process renames first, so the explicit rows (which carry the new id) overlay the
	// rewritten maps and reference rewrites cover every row pointing at the old id.
	for i, rename := range bundle.Renames {
		path := fmt.Sprintf("renames[%d]", i)
		if err := candidate.applyRename(rename, path); err != nil {
			return nil, err
		}
	}

	for i, role := range bundle.Roles {
		id := role.GetId()
		candidate.explicitRoles[id] = cloneRole(role)
		candidate.roleMap[id] = cloneRole(role)
		candidate.explicitRoleIndex[id] = i

		rev := bundle.Revisions[id]
		if rev == "" {
			rev = liveRoleRevision[id]
		}
		candidate.refs = append(candidate.refs, PolicyBundleObjectRef{
			Kind: "role", Id: id, Revision: rev, Action: candidate.upsertAction(rev),
		})
	}
	for i, group := range bundle.Groups {
		id := group.GetId()
		candidate.explicitGroups[id] = cloneGroup(group)
		candidate.groupMap[id] = cloneGroup(group)
		candidate.explicitGroupIndex[id] = i

		rev := bundle.Revisions[id]
		if rev == "" {
			rev = liveGroupRevision[id]
		}
		candidate.refs = append(candidate.refs, PolicyBundleObjectRef{
			Kind: "group", Id: id, Revision: rev, Action: candidate.upsertAction(rev),
		})
	}
	for i, permission := range bundle.Permissions {
		id := permission.GetId()
		candidate.explicitPerms[id] = clonePermission(permission)
		candidate.permMap[id] = clonePermission(permission)
		candidate.explicitPermIndex[id] = i

		rev := bundle.Revisions[id]
		if rev == "" {
			rev = livePermRevision[id]
		}
		candidate.refs = append(candidate.refs, PolicyBundleObjectRef{
			Kind: "permission", Id: id, Revision: rev, Action: candidate.upsertAction(rev),
		})
	}

	// Rename refs use the original row revision and a "rename" action.
	for _, rename := range bundle.Renames {
		var rev string
		switch rename.Kind {
		case "role":
			rev = liveRoleRevision[rename.OldId]
		case "group":
			rev = liveGroupRevision[rename.OldId]
		case "permission":
			rev = livePermRevision[rename.OldId]
		}
		if supplied := bundle.Revisions[rename.OldId]; supplied != "" {
			rev = supplied
		}
		candidate.refs = append(candidate.refs, PolicyBundleObjectRef{
			Kind: rename.Kind, Id: rename.OldId, Revision: rev, Action: "rename",
		})
	}

	digest, err := candidate.computeModelAdapterDigest()
	if err != nil {
		return nil, err
	}
	candidate.modelAdapterDigest = digest

	return candidate, nil
}

func (c *bundleCandidate) upsertAction(revision string) string {
	if revision == "" {
		return "insert"
	}
	return "update"
}

func (c *bundleCandidate) applyRename(rename PolicyBundleRename, path string) error {
	oldOwner, oldName, err := util.GetOwnerAndNameFromIdWithError(rename.OldId)
	if err != nil {
		return bundleError(path, "the old id %q is invalid: %w", rename.OldId, err)
	}
	newOwner, newName, err := util.GetOwnerAndNameFromIdWithError(rename.NewId)
	if err != nil {
		return bundleError(path, "the new id %q is invalid: %w", rename.NewId, err)
	}
	if oldOwner != c.owner || newOwner != c.owner {
		return bundleError(path, "renames must stay inside the bundle owner %q", c.owner)
	}
	if oldName == newName {
		return bundleError(path, "the old id and new id are identical: %s", rename.OldId)
	}

	switch rename.Kind {
	case "role":
		role, ok := c.roleMap[rename.OldId]
		if !ok {
			return bundleError(path, "the role %q to rename does not exist", rename.OldId)
		}
		if _, conflict := c.roleMap[rename.NewId]; conflict {
			return bundleError(path, "the target role id %q already exists", rename.NewId)
		}
		newRole := cloneRole(role)
		newRole.Owner, newRole.Name = newOwner, newName
		delete(c.roleMap, rename.OldId)
		c.roleMap[rename.NewId] = newRole

		for _, other := range c.roleMap {
			changed := false
			for j, subId := range other.Roles {
				if subId == rename.OldId {
					other.Roles[j] = rename.NewId
					changed = true
				}
			}
			if changed {
				if _, explicit := c.explicitRoles[other.GetId()]; !explicit {
					c.rewrittenRoles[other.GetId()] = cloneRole(other)
				}
			}
		}
		for _, permission := range c.permMap {
			changed := false
			for j, roleId := range permission.Roles {
				if roleId == rename.OldId {
					permission.Roles[j] = rename.NewId
					changed = true
				}
			}
			if changed {
				if _, explicit := c.explicitPerms[permission.GetId()]; !explicit {
					c.rewrittenPerms[permission.GetId()] = clonePermission(permission)
				}
			}
		}
	case "group":
		group, ok := c.groupMap[rename.OldId]
		if !ok {
			return bundleError(path, "the group %q to rename does not exist", rename.OldId)
		}
		if _, conflict := c.groupMap[rename.NewId]; conflict {
			return bundleError(path, "the target group id %q already exists", rename.NewId)
		}
		newGroup := cloneGroup(group)
		newGroup.Owner, newGroup.Name = newOwner, newName
		delete(c.groupMap, rename.OldId)
		c.groupMap[rename.NewId] = newGroup

		for _, role := range c.roleMap {
			changed := false
			for j, groupId := range role.Groups {
				if groupId == rename.OldId {
					role.Groups[j] = rename.NewId
					changed = true
				}
			}
			if changed {
				if _, explicit := c.explicitRoles[role.GetId()]; !explicit {
					c.rewrittenRoles[role.GetId()] = cloneRole(role)
				}
			}
		}
		for _, permission := range c.permMap {
			changed := false
			for j, groupId := range permission.Groups {
				if groupId == rename.OldId {
					permission.Groups[j] = rename.NewId
					changed = true
				}
			}
			if changed {
				if _, explicit := c.explicitPerms[permission.GetId()]; !explicit {
					c.rewrittenPerms[permission.GetId()] = clonePermission(permission)
				}
			}
		}
	case "permission":
		permission, ok := c.permMap[rename.OldId]
		if !ok {
			return bundleError(path, "the permission %q to rename does not exist", rename.OldId)
		}
		if _, conflict := c.permMap[rename.NewId]; conflict {
			return bundleError(path, "the target permission id %q already exists", rename.NewId)
		}
		newPermission := clonePermission(permission)
		newPermission.Owner, newPermission.Name = newOwner, newName
		delete(c.permMap, rename.OldId)
		c.permMap[rename.NewId] = newPermission
	default:
		return bundleError(path, "unknown rename kind %q, allowed values are role, group and permission", rename.Kind)
	}
	return nil
}

// computeModelAdapterDigest hashes the model texts and adapter rows referenced by the
// candidate permissions, so a model or adapter change silently invalidates the plan.
func (c *bundleCandidate) computeModelAdapterDigest() (string, error) {
	pairs := []string{}
	seen := map[string]struct{}{}

	for _, id := range sortedPermIds(c.permMap) {
		permission := c.permMap[id]
		modelId := permission.Model
		if _, ok := seen["model:"+modelId]; !ok {
			seen["model:"+modelId] = struct{}{}
			if modelId != "" {
				model, err := getModelEx(modelId)
				if err != nil {
					return "", err
				}
				if model == nil {
					pairs = append(pairs, "model:"+modelId+"=<missing>")
				} else {
					pairs = append(pairs, "model:"+modelId+"="+model.ModelText)
				}
			} else {
				pairs = append(pairs, "model:=<built-in>")
			}
		}

		adapterName := permission.Adapter
		key := "adapter:" + util.GetId(permission.Owner, adapterName)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			if adapterName == "" {
				pairs = append(pairs, key+"=<built-in>")
				continue
			}
			adapter, err := getAdapter(permission.Owner, adapterName)
			if err != nil {
				return "", err
			}
			if adapter == nil {
				pairs = append(pairs, key+"=<missing>")
			} else {
				pairs = append(pairs, key+"="+bundleRevision(adapter))
			}
		}
	}
	sort.Strings(pairs)
	return digestJSON(pairs), nil
}

// validateCandidate runs every pre-write check and builds the real Casbin enforcers for
// the whole snapshot: a JSON-parseable policy that cannot be loaded or executed is
// reported here, before the live enforcer or adapter is touched.
func (c *bundleCandidate) validateCandidate(bundle *PolicyBundle) error {
	if err := c.validateRoleReferences(); err != nil {
		return err
	}
	if err := c.validateRoleCycles(); err != nil {
		return err
	}
	if err := c.validatePermissionReferences(); err != nil {
		return err
	}
	if err := c.validateModelsAndAdapters(); err != nil {
		return err
	}
	if err := c.validateEnforcers(); err != nil {
		return err
	}
	return c.validateCorpus(bundle)
}

func (c *bundleCandidate) validateRoleReferences() error {
	for _, id := range sortedRoleIds(c.roleMap) {
		role := c.roleMap[id]
		index := c.roleIndex(id)
		for j, subId := range role.Roles {
			if subId == "*" {
				continue
			}
			path := fmt.Sprintf("roles[%d].roles[%d]", index, j)
			subOwner, _, err := util.GetOwnerAndNameFromIdWithError(subId)
			if err != nil {
				return bundleError(path, "the role reference %q is invalid: %w", subId, err)
			}
			if subOwner != c.owner {
				return bundleError(path,
					"the role %q references %q of another organization: cross-owner references are not allowed", id, subId)
			}
			if _, ok := c.roleMap[subId]; !ok {
				return bundleError(path, "the role %q references the missing role %q", id, subId)
			}
		}
	}
	return nil
}

func (c *bundleCandidate) roleIndex(id string) int {
	if index, ok := c.explicitRoleIndex[id]; ok {
		return index
	}
	// rows outside the explicit set keep a stable, collision-free index range
	for offset, sortedId := range sortedRoleIds(c.roleMap) {
		if sortedId == id {
			return len(c.explicitRoleIndex) + offset
		}
	}
	return -1
}

// validateRoleCycles detects role inheritance cycles with a colored DFS and reports the
// id path that closes the cycle.
func (c *bundleCandidate) validateRoleCycles() error {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	colors := map[string]int{}
	var stack []string

	var visit func(roleId string) error
	visit = func(roleId string) error {
		if colors[roleId] == gray {
			cycle := append([]string{}, stack...)
			for i, id := range cycle {
				if id == roleId {
					cycle = cycle[i:]
					break
				}
			}
			return bundleError("roles", "a circular role inheritance was detected: %s -> %s",
				strings.Join(cycle, " -> "), roleId)
		}
		if colors[roleId] == black {
			return nil
		}
		colors[roleId] = gray
		stack = append(stack, roleId)
		role, ok := c.roleMap[roleId]
		if ok {
			for _, subId := range role.Roles {
				if subId == "*" {
					continue
				}
				if _, exists := c.roleMap[subId]; !exists {
					continue
				}
				if err := visit(subId); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		colors[roleId] = black
		return nil
	}

	for _, id := range sortedRoleIds(c.roleMap) {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func (c *bundleCandidate) validatePermissionReferences() error {
	for _, id := range sortedPermIds(c.permMap) {
		permission := c.permMap[id]
		index := c.permIndex(id)
		for j, roleId := range permission.Roles {
			if roleId == "*" {
				continue
			}
			path := fmt.Sprintf("permissions[%d].roles[%d]", index, j)
			roleOwner, _, err := util.GetOwnerAndNameFromIdWithError(roleId)
			if err != nil {
				return bundleError(path, "the role reference %q is invalid: %w", roleId, err)
			}
			if roleOwner != c.owner {
				return bundleError(path,
					"the permission %q references %q of another organization: cross-owner references are not allowed", id, roleId)
			}
			if _, ok := c.roleMap[roleId]; !ok {
				return bundleError(path, "the permission %q references the missing role %q", id, roleId)
			}
		}
		for j, groupId := range permission.Groups {
			if groupId == "*" {
				continue
			}
			path := fmt.Sprintf("permissions[%d].groups[%d]", index, j)
			canonical := getPermissionGroupId(permission.Owner, groupId)
			groupOwner, _, err := util.GetOwnerAndNameFromIdWithError(canonical)
			if err != nil {
				return bundleError(path, "the group reference %q is invalid: %w", groupId, err)
			}
			if groupOwner != c.owner {
				return bundleError(path,
					"the permission %q references %q of another organization: cross-owner references are not allowed", id, groupId)
			}
			if _, ok := c.groupMap[canonical]; !ok {
				return bundleError(path, "the permission %q references the missing group %q", id, canonical)
			}
		}
	}
	return nil
}

func (c *bundleCandidate) validateModelsAndAdapters() error {
	for _, id := range sortedPermIds(c.permMap) {
		permission := c.permMap[id]
		index := c.permIndex(id)
		path := fmt.Sprintf("permissions[%d].model", index)

		if permission.Model != "" {
			model, err := getModelEx(permission.Model)
			if err != nil {
				return bundleError(path, "failed to load the model %q: %w", permission.Model, err)
			}
			if model == nil {
				return bundleError(path, "the model %q does not exist", permission.Model)
			}
			if _, err := casbinmodel.NewModelFromString(model.ModelText); err != nil {
				return bundleError(path, "the model %q is not a legal Casbin model: %w", permission.Model, err)
			}
			if _, err := GetBuiltInModel(model.ModelText); err != nil {
				return bundleError(path, "the model %q cannot be used by permissions: %w", permission.Model, err)
			}
		} else {
			if _, err := GetBuiltInModel(""); err != nil {
				return bundleError(path, "the built-in model cannot be initialized: %w", err)
			}
		}

		if err := checkPermissionModel(permission); err != nil {
			return bundleError(path, "%w", err)
		}

		if permission.Adapter != "" {
			adapterPath := fmt.Sprintf("permissions[%d].adapter", index)
			adapter, err := getAdapter(permission.Owner, permission.Adapter)
			if err != nil {
				return bundleError(adapterPath, "failed to load the adapter %q: %w", permission.Adapter, err)
			}
			if adapter == nil {
				return bundleError(adapterPath, "the adapter %q does not exist", permission.Adapter)
			}
			if !adapter.UseSameDb && adapter.Owner != "built-in" {
				c.unsupportedReason = fmt.Sprintf(
					"the adapter %q of permission %q is an external independent policy adapter without an atomic publish protocol",
					adapter.GetId(), id)
				return fmt.Errorf("%w: %s", ErrPolicyBundleUnsupported, c.unsupportedReason)
			}
		}
	}
	return nil
}

// validateEnforcers constructs one real in-memory enforcer per model/adapter group of
// the whole snapshot, proving the candidate policies are executable rather than merely
// parseable JSON.
func (c *bundleCandidate) validateEnforcers() error {
	permissions := make([]*Permission, 0, len(c.permMap))
	for _, id := range sortedPermIds(c.permMap) {
		permissions = append(permissions, c.permMap[id])
	}
	groups := GroupPermissionsByModelAdapter(permissions)
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		permissionIds := groups[key]
		representative := c.permMap[permissionIds[0]]
		if representative == nil {
			return bundleError("policies", "the representative permission %q is missing from the snapshot", permissionIds[0])
		}
		if _, err := c.buildEnforcer(representative, permissionIds); err != nil {
			return bundleError(fmt.Sprintf("policies[%s]", key), "%w", err)
		}
	}
	return nil
}

func (c *bundleCandidate) validateCorpus(bundle *PolicyBundle) error {
	enforcerCache := map[string]*casbin.Enforcer{}
	for i, corpusRequest := range bundle.RequestCorpus {
		path := fmt.Sprintf("requestCorpus[%d]", i)
		permission := c.permMap[corpusRequest.PermissionId]
		if permission == nil {
			return bundleError(path, "the permission %q is not part of the candidate snapshot", corpusRequest.PermissionId)
		}
		key := permission.GetModelAndAdapter()
		enforcer, ok := enforcerCache[key]
		if !ok {
			var err error
			enforcer, err = c.buildEnforcer(permission, nil)
			if err != nil {
				return bundleError(path, "%w", err)
			}
			enforcerCache[key] = enforcer
		}
		request := util.InterfaceToEnforceArray(corpusRequest.Request)
		allowed, err := enforcer.Enforce(request...)
		if err != nil {
			return bundleError(path, "the candidate enforcer failed to execute the request: %w", err)
		}
		if corpusRequest.ExpectAllow != nil && *corpusRequest.ExpectAllow != allowed {
			return bundleError(path, "the regression request expected allow=%v but the candidate enforcer decided allow=%v",
				*corpusRequest.ExpectAllow, allowed)
		}
	}
	return nil
}

// buildEnforcer builds an isolated in-memory Casbin enforcer for the candidate
// snapshot. It never sets a persistence adapter, so planning cannot modify the live
// adapter or any policy table.
func (c *bundleCandidate) buildEnforcer(representative *Permission, permissionIDs []string) (*casbin.Enforcer, error) {
	var modelText string
	if representative.Model != "" {
		model, err := getModelEx(representative.Model)
		if err != nil {
			return nil, err
		}
		if model == nil {
			return nil, fmt.Errorf("the model: %s for permission: %s is not found", representative.Model, representative.GetId())
		}
		modelText = model.ModelText
	}
	m, err := GetBuiltInModel(modelText)
	if err != nil {
		return nil, err
	}

	enforcer, err := casbin.NewEnforcer(&casbinlog.DefaultLogger{}, false)
	if err != nil {
		return nil, err
	}
	err = enforcer.InitWithModelAndAdapter(m, nil)
	if err != nil {
		return nil, err
	}
	enforcer.EnableAutoSave(false)

	targets := []*Permission{}
	if len(permissionIDs) == 0 {
		if permission := c.permMap[representative.GetId()]; permission != nil {
			targets = []*Permission{permission}
		} else {
			targets = []*Permission{representative}
		}
	} else {
		for _, id := range permissionIDs {
			if permission := c.permMap[id]; permission != nil {
				targets = append(targets, permission)
			}
		}
	}

	policies := [][]string{}
	for _, permission := range targets {
		policies = append(policies, getPolicies(permission)...)
	}
	if _, err = enforcer.AddPolicies(policies); err != nil {
		return nil, err
	}

	if HasRoleDefinition(enforcer.GetModel()) {
		groupingPolicies, err := c.getRuntimeGroupingPolicies(targets)
		if err != nil {
			return nil, err
		}
		if len(groupingPolicies) != 0 {
			if _, err = enforcer.AddGroupingPolicies(groupingPolicies); err != nil {
				return nil, err
			}
		}
	}

	return enforcer, nil
}

// getRolesInRole resolves the role hierarchy purely from the candidate snapshot.
func (c *bundleCandidate) getRolesInRole(permissionOwner string, roleId string, visited map[string]struct{}) ([]*Role, error) {
	if roleId == "*" {
		roleId = util.GetId(permissionOwner, "*")
	}
	roleOwner, roleName, err := util.GetOwnerAndNameFromIdWithError(roleId)
	if err != nil {
		return []*Role{}, err
	}
	if roleName == "*" {
		roles := []*Role{}
		for _, id := range sortedRoleIds(c.roleMap) {
			role := c.roleMap[id]
			if role.Owner == roleOwner {
				roles = append(roles, role)
			}
		}
		return roles, nil
	}

	role := c.roleMap[roleId]
	if role == nil {
		return []*Role{}, nil
	}
	visited[roleId] = struct{}{}

	roles := []*Role{role}
	for _, subRoleId := range role.Roles {
		if _, ok := visited[subRoleId]; ok {
			continue
		}
		subRoles, err := c.getRolesInRole(roleOwner, subRoleId, visited)
		if err != nil {
			return []*Role{}, err
		}
		roles = append(roles, subRoles...)
	}
	return roles, nil
}

// getUsersInGroup resolves group memberships for the candidate view. Users are not
// bundle objects, so their current group bindings are read from the live user rows; the
// candidate only controls which groups and roles exist.
func (c *bundleCandidate) getUsersInGroup(permissionOwner string, groupId string) ([]string, error) {
	groupId = getPermissionGroupId(permissionOwner, groupId)
	groupOwner, groupName, err := util.GetOwnerAndNameFromIdWithError(groupId)
	if err != nil {
		return nil, err
	}

	users, err := GetGlobalUsers()
	if err != nil {
		return nil, err
	}

	userIds := map[string]struct{}{}
	for _, user := range users {
		if user.Owner != groupOwner {
			continue
		}
		if groupName == "*" {
			if len(user.Groups) > 0 {
				userIds[user.GetId()] = struct{}{}
			}
			continue
		}
		if util.InSlice(user.Groups, groupId) {
			userIds[user.GetId()] = struct{}{}
		}
	}

	result := make([]string, 0, len(userIds))
	for userId := range userIds {
		result = append(result, userId)
	}
	sort.Strings(result)
	return result, nil
}

// getRuntimeGroupingPolicies is the candidate-snapshot twin of the production
// getRuntimeGroupingPolicies. The rule shape stays identical, only the data source
// changes from database lookups to the merged snapshot.
func (c *bundleCandidate) getRuntimeGroupingPolicies(permissions []*Permission) ([][]string, error) {
	var groupingPolicies [][]string
	visitedPolicies := map[string]struct{}{}

	for _, permission := range permissions {
		domainExist := len(permission.Domains) > 0
		for _, groupId := range permission.Groups {
			groupSubject := getPermissionGroupSubject(permission.Owner, groupId)
			users, err := c.getUsersInGroup(permission.Owner, groupId)
			if err != nil {
				return nil, err
			}
			for _, user := range users {
				if domainExist {
					for _, domain := range permission.Domains {
						appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(user, groupSubject, domain))
					}
				} else {
					appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(user, groupSubject, ""))
				}
			}
		}

		for _, roleId := range permission.Roles {
			visited := map[string]struct{}{}
			rolesInRole, err := c.getRolesInRole(permission.Owner, roleId, visited)
			if err != nil {
				return nil, err
			}
			for _, role := range rolesInRole {
				currentRoleID := role.GetId()
				for _, subUser := range role.Users {
					if domainExist {
						for _, domain := range permission.Domains {
							appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(subUser, currentRoleID, domain))
						}
					} else {
						appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(subUser, currentRoleID, ""))
					}
				}
				for _, subGroup := range role.Groups {
					groupSubject := getPermissionGroupSubject(role.Owner, subGroup)
					if domainExist {
						for _, domain := range permission.Domains {
							appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(groupSubject, currentRoleID, domain))
						}
					} else {
						appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(groupSubject, currentRoleID, ""))
					}
					users, err := c.getUsersInRoleGroup(role.Owner, subGroup)
					if err != nil {
						return nil, err
					}
					for _, user := range users {
						if domainExist {
							for _, domain := range permission.Domains {
								appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(user, groupSubject, domain))
							}
						} else {
							appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(user, groupSubject, ""))
						}
					}
				}
				for _, subRole := range role.Roles {
					if domainExist {
						for _, domain := range permission.Domains {
							appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(subRole, currentRoleID, domain))
						}
					} else {
						appendRuntimeGroupingPolicy(&groupingPolicies, visitedPolicies, newRuntimeGroupingPolicy(subRole, currentRoleID, ""))
					}
				}
			}
		}
	}

	return groupingPolicies, nil
}

func (c *bundleCandidate) getUsersInRoleGroup(owner string, groupId string) ([]string, error) {
	if _, ok := c.groupMap[getPermissionGroupId(owner, groupId)]; !ok {
		return []string{}, nil
	}
	return c.getUsersInGroup(owner, groupId)
}

func (c *bundleCandidate) permIndex(id string) int {
	if index, ok := c.explicitPermIndex[id]; ok {
		return index
	}
	for offset, sortedId := range sortedPermIds(c.permMap) {
		if sortedId == id {
			return len(c.explicitPermIndex) + offset
		}
	}
	return -1
}

// preparePolicyBundle builds the isolated candidate, runs every pre-write validation and
// executes the regression corpus. It is shared by the plan endpoint and the publish
// endpoint, which re-runs it outside the transaction before committing.
func preparePolicyBundle(bundle *PolicyBundle) (*bundleCandidate, *PolicyBundlePlanResult, error) {
	candidate, err := buildBundleCandidate(bundle)
	if err != nil {
		return nil, nil, err
	}

	result := &PolicyBundlePlanResult{
		Owner:              bundle.Owner,
		ModelAdapterDigest: candidate.modelAdapterDigest,
		Snapshot:           candidate.snapshot(),
		Objects:            append([]PolicyBundleObjectRef{}, candidate.refs...),
		Supported:          true,
	}

	if err := candidate.validateCandidate(bundle); err != nil {
		if errors.Is(err, ErrPolicyBundleUnsupported) {
			result.Supported = false
			result.UnsupportedReason = candidate.unsupportedReason
			result.Digest = candidate.planDigest(bundle)
			return candidate, result, err
		}
		return nil, nil, err
	}

	decisions, err := candidate.runCorpusWithLiveBaseline(bundle)
	if err != nil {
		return nil, nil, err
	}
	result.Decisions = decisions
	result.Digest = candidate.planDigest(bundle)
	return candidate, result, nil
}

// PlanPolicyBundle validates the bundle and executes the regression corpus against
// isolated candidate enforcers. It performs no database writes and never instantiates a
// persistence adapter for the candidate policies.
func PlanPolicyBundle(bundle *PolicyBundle) (*PolicyBundlePlanResult, error) {
	_, result, err := preparePolicyBundle(bundle)
	return result, err
}

func (c *bundleCandidate) planDigest(bundle *PolicyBundle) string {
	payload := struct {
		Owner              string                  `json:"owner"`
		Renames            []PolicyBundleRename    `json:"renames"`
		Objects            []PolicyBundleObjectRef `json:"objects"`
		ModelAdapterDigest string                  `json:"modelAdapterDigest"`
		Snapshot           *PolicyBundleSnapshot   `json:"snapshot"`
		Corpus             []PolicyBundleRequest   `json:"corpus"`
	}{
		Owner:              bundle.Owner,
		Renames:            bundle.Renames,
		Objects:            c.refs,
		ModelAdapterDigest: c.modelAdapterDigest,
		Snapshot:           c.snapshot(),
		Corpus:             bundle.RequestCorpus,
	}
	return digestJSON(payload)
}

// runCorpusWithLiveBaseline enforces every corpus request against both the isolated
// candidate enforcer and an independent enforcer built from the current live database
// state, so decisions can be compared per request.
func (c *bundleCandidate) runCorpusWithLiveBaseline(bundle *PolicyBundle) ([]PolicyBundleRequestDecision, error) {
	enforcerCache := map[string]*casbin.Enforcer{}
	decisions := make([]PolicyBundleRequestDecision, 0, len(bundle.RequestCorpus))

	for i, corpusRequest := range bundle.RequestCorpus {
		decision := PolicyBundleRequestDecision{
			Index:        i,
			PermissionId: corpusRequest.PermissionId,
			Request:      append([]interface{}{}, corpusRequest.Request...),
			ExpectAllow:  corpusRequest.ExpectAllow,
		}

		permission := c.permMap[corpusRequest.PermissionId]
		if permission == nil {
			return nil, bundleError(fmt.Sprintf("requestCorpus[%d]", i),
				"the permission %q is not part of the candidate snapshot", corpusRequest.PermissionId)
		}

		key := permission.GetModelAndAdapter()
		enforcer, ok := enforcerCache[key]
		if !ok {
			var err error
			enforcer, err = c.buildEnforcer(permission, nil)
			if err != nil {
				return nil, bundleError(fmt.Sprintf("requestCorpus[%d]", i), "%w", err)
			}
			enforcerCache[key] = enforcer
		}
		candidateRequest := util.InterfaceToEnforceArray(corpusRequest.Request)
		candidateAllow, err := enforcer.Enforce(candidateRequest...)
		if err != nil {
			return nil, bundleError(fmt.Sprintf("requestCorpus[%d]", i),
				"the candidate enforcer failed to execute the request: %w", err)
		}
		decision.CandidateAllow = candidateAllow

		livePermission, err := GetPermission(corpusRequest.PermissionId)
		if err != nil {
			return nil, err
		}
		if livePermission != nil {
			liveEnforcer, err := getPermissionEnforcer(livePermission)
			if err != nil {
				return nil, bundleError(fmt.Sprintf("requestCorpus[%d]", i),
					"failed to build the independent live enforcer: %w", err)
			}
			liveRequest := util.InterfaceToEnforceArray(corpusRequest.Request)
			liveAllow, err := liveEnforcer.Enforce(liveRequest...)
			if err != nil {
				return nil, bundleError(fmt.Sprintf("requestCorpus[%d]", i),
					"the independent live enforcer failed to execute the request: %w", err)
			}
			decision.HasLiveDecision = true
			decision.LiveAllow = liveAllow
		}

		decision.Matched = !decision.HasLiveDecision || decision.CandidateAllow == decision.LiveAllow
		if corpusRequest.ExpectAllow != nil {
			decision.Matched = decision.Matched && *corpusRequest.ExpectAllow == candidateAllow
		}
		decisions = append(decisions, decision)
	}
	return decisions, nil
}
