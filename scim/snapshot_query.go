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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/scim2/filter-parser/v2"
	"github.com/xorm-io/builder"
)

const (
	// SnapshotTokenHeader carries the opaque token back to the client on creation and
	// accepts the same token on later page requests.
	SnapshotTokenHeader = "X-Casdoor-Scim-Snapshot-Token"

	snapshotQueryToken  = "snapshotToken"
	snapshotQueryMode   = "snapshot"
	snapshotModeCreate  = "create"
	snapshotModeRelease = "release"
)

type snapshotMode int

const (
	snapshotOff snapshotMode = iota
	snapshotCreate
	snapshotConsume
)

// snapshotKind binds one SCIM endpoint to its filter translator and the sort columns
// its schema allows.
type snapshotKind struct {
	name        string
	attrCond    attributeCond
	sortColumns map[string]string
}

var userSnapshotKind = snapshotKind{
	name:        "User",
	attrCond:    userFilterCond,
	sortColumns: userSnapshotSortColumns,
}

var groupSnapshotKind = snapshotKind{
	name:        "Group",
	attrCond:    groupFilterCond,
	sortColumns: groupSnapshotSortColumns,
}

// Only scalar, indexed schema attributes may drive the frozen ordering.
var userSnapshotSortColumns = map[string]string{
	"externalid":         "external_id",
	"username":           "name",
	"displayname":        "display_name",
	"usertype":           "type",
	"profileurl":         "homepage",
	"name.givenname":     "first_name",
	"name.familyname":    "last_name",
	"emails":             "email",
	"emails.value":       "email",
	"phonenumbers":       "phone",
	"phonenumbers.value": "phone",
	"photos":             "avatar",
	"photos.value":       "avatar",
	"addresses.locality": "location",
	"addresses.region":   "region",
	"addresses.country":  "country_code",
	"organization":       "owner",
}

var groupSnapshotSortColumns = map[string]string{
	"displayname":  "display_name",
	"organization": "owner",
}

type snapshotQuery struct {
	mode        snapshotMode
	token       string
	filterCanon string
	sortByCanon string
	sortColumn  string
	descending  bool
	sortOrder   string
	include     []attrRequest
	exclude     []attrRequest
	includeRaw  []string
	excludeRaw  []string
}

// attrRequest is a normalized attributes/excludedAttributes entry. uri is set for
// extension schema attributes, name is the lower-cased top-level attribute and sub the
// optional lower-cased sub-attribute.
type attrRequest struct {
	uri  string
	name string
	sub  string
}

func parseAttrRequest(raw string) attrRequest {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	for _, extensionURI := range []string{strings.ToLower(UserExtensionKey), strings.ToLower(GroupExtensionKey)} {
		if lower == extensionURI {
			return attrRequest{uri: extensionURI, name: extensionURI}
		}
		if strings.HasPrefix(lower, extensionURI+".") {
			return attrRequest{uri: extensionURI, name: extensionURI, sub: strings.TrimPrefix(lower, extensionURI+".")}
		}
	}
	name, sub, found := strings.Cut(lower, ".")
	if found {
		return attrRequest{name: name, sub: sub}
	}
	return attrRequest{name: name}
}

func canonicalAttrList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	set := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			set[part] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func requestsFromCanonical(values []string) []attrRequest {
	requests := make([]attrRequest, 0, len(values))
	for _, value := range values {
		requests = append(requests, parseAttrRequest(value))
	}
	return requests
}

// canonicalFilter renders the parsed filter into a deterministic string: attribute
// names and operators are lower-cased while string compare values keep their exact
// quoted form. Two semantically equal filters therefore share one binding digest.
func canonicalFilter(expr filter.Expression) string {
	switch e := expr.(type) {
	case *filter.LogicalExpression:
		return fmt.Sprintf("%s %s %s", canonicalFilter(e.Left), strings.ToLower(string(e.Operator)), canonicalFilter(e.Right))
	case *filter.NotExpression:
		return "not(" + canonicalFilter(e.Expression) + ")"
	case *filter.ValuePath:
		return canonicalAttrPath(e.AttributePath) + "[" + canonicalFilter(e.ValueFilter) + "]"
	case *filter.AttributeExpression:
		result := canonicalAttrPath(e.AttributePath) + " " + strings.ToLower(string(e.Operator))
		if e.CompareValue != nil {
			if value, ok := e.CompareValue.(string); ok {
				result += " " + strconv.Quote(value)
			} else {
				result += " " + fmt.Sprintf("%v", e.CompareValue)
			}
		}
		return result
	default:
		return ""
	}
}

func canonicalAttrPath(path filter.AttributePath) string {
	name := strings.ToLower(path.AttributeName)
	if path.URIPrefix != nil {
		name = strings.ToLower(*path.URIPrefix) + ":" + name
	}
	if path.SubAttribute != nil {
		name += "." + strings.ToLower(*path.SubAttribute)
	}
	return name
}

func snapshotTokenFromRequest(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get(SnapshotTokenHeader)); token != "" {
		return token
	}
	return strings.TrimSpace(r.URL.Query().Get(snapshotQueryToken))
}

func badSnapshotRequest(detail string) error {
	return scimerrors.ScimErrorBadRequest(detail)
}

// parseSnapshotQuery returns snapshotOff when the request is an ordinary SCIM list,
// keeping the default interface untouched.
func parseSnapshotQuery(r *http.Request, params scim.ListRequestParams, kind snapshotKind) (*snapshotQuery, error) {
	manager := getSnapshotManager()
	if manager == nil {
		return &snapshotQuery{mode: snapshotOff}, nil
	}

	query := &snapshotQuery{mode: snapshotOff}
	if token := snapshotTokenFromRequest(r); token != "" {
		query.mode = snapshotConsume
		query.token = token
	}

	mode := strings.TrimSpace(r.URL.Query().Get(snapshotQueryMode))
	switch mode {
	case "":
	case snapshotModeCreate, "true":
		if query.mode == snapshotOff {
			query.mode = snapshotCreate
		}
	case snapshotModeRelease:
		// Handled by the controller before the SCIM server dispatches the list.
	default:
		return nil, badSnapshotRequest("the snapshot query parameter only accepts create or release")
	}

	if query.mode == snapshotOff {
		return query, nil
	}

	if params.Filter != nil {
		query.filterCanon = canonicalFilter(params.Filter)
	}

	sortBy := strings.TrimSpace(r.URL.Query().Get("sortBy"))
	sortOrder := strings.TrimSpace(r.URL.Query().Get("sortOrder"))
	if sortBy == "" {
		if sortOrder != "" {
			return nil, badSnapshotRequest("sortOrder requires sortBy")
		}
		// Mirror the ordinary list default: newest first, made total by the id tie-breaker.
		query.sortColumn = "created_time"
		query.descending = true
		query.sortOrder = "descending"
	} else {
		column, ok := kind.sortColumns[strings.ToLower(sortBy)]
		if !ok {
			return nil, badSnapshotRequest("sorting the resource by the attribute: " + sortBy + " is not supported")
		}
		query.sortByCanon = strings.ToLower(sortBy)
		query.sortColumn = column
		switch strings.ToLower(sortOrder) {
		case "", "ascending":
			query.sortOrder = "ascending"
		case "descending":
			query.descending = true
			query.sortOrder = "descending"
		default:
			return nil, badSnapshotRequest("sortOrder only accepts ascending or descending")
		}
	}

	includeRaw := canonicalAttrList(r.URL.Query().Get("attributes"))
	excludeRaw := canonicalAttrList(r.URL.Query().Get("excludedAttributes"))
	if len(includeRaw) > 0 && len(excludeRaw) > 0 {
		return nil, badSnapshotRequest("attributes and excludedAttributes must not be used together")
	}
	query.includeRaw = includeRaw
	query.excludeRaw = excludeRaw
	query.include = requestsFromCanonical(includeRaw)
	query.exclude = requestsFromCanonical(excludeRaw)
	return query, nil
}

func subjectPermissionGen(user *object.User) string {
	hash := sha256.New()
	fmt.Fprintf(hash, "%s\n%s\n%t\n%t\n%t\n%s",
		user.Owner, user.Name, user.IsAdmin, user.IsForbidden, user.IsDeleted, user.UpdatedTime)
	return hex.EncodeToString(hash.Sum(nil))
}

// validateSnapshotSubject re-runs the authorization of the creating call on every page
// request. A demoted, forbidden or deleted caller changes the permission generation and
// is rejected even while the artifact remains physically present.
func validateSnapshotSubject(r *http.Request, organization, subject, permGen string) error {
	user, err := object.GetUser(subject)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrSnapshotTokenInvalid
	}
	if user.IsForbidden || user.IsDeleted {
		return ErrSnapshotBindingMismatch
	}
	if organization == "" {
		if user.Owner != "built-in" {
			return ErrSnapshotBindingMismatch
		}
	} else if user.Owner != organization || !user.IsAdmin {
		return ErrSnapshotBindingMismatch
	}
	if subjectPermissionGen(user) != permGen {
		return ErrSnapshotBindingMismatch
	}
	return nil
}

func frozenCondition(params scim.ListRequestParams, kind snapshotKind) (builder.Cond, error) {
	cond := builder.NewCond()
	if params.Filter != nil {
		var err error
		cond, err = filterToCond(params.Filter, nil, kind.attrCond)
		if err != nil {
			return nil, err
		}
	}
	return cond, nil
}

// handleSnapshotList runs the opt-in snapshot branch and reports whether it handled the
// request. A false result leaves the ordinary GetAll behavior completely untouched.
func handleSnapshotList(r *http.Request, params scim.ListRequestParams, kind snapshotKind) (scim.Page, bool, error) {
	query, err := parseSnapshotQuery(r, params, kind)
	if err != nil {
		return scim.Page{}, true, err
	}
	if query.mode == snapshotOff {
		return scim.Page{}, false, nil
	}
	manager := getSnapshotManager()
	if manager == nil {
		return scim.Page{}, false, nil
	}

	organization, err := getOrganization(r)
	if err != nil {
		return scim.Page{}, true, err
	}
	subject, err := getSubject(r)
	if err != nil {
		return scim.Page{}, true, err
	}

	if query.mode == snapshotConsume {
		return consumeSnapshot(r, manager, query, params, organization, subject, kind)
	}
	return createSnapshot(r, manager, query, params, organization, subject, kind)
}

func createSnapshot(
	r *http.Request,
	manager *snapshotManager,
	query *snapshotQuery,
	params scim.ListRequestParams,
	organization, subject string,
	kind snapshotKind,
) (scim.Page, bool, error) {
	cond, err := frozenCondition(params, kind)
	if err != nil {
		return scim.Page{}, true, err
	}

	user, err := object.GetUser(subject)
	if err != nil {
		return scim.Page{}, true, err
	}
	if user == nil {
		return scim.Page{}, true, ErrSnapshotTokenInvalid
	}

	now := time.Now()
	envelope := &snapshotEnvelope{
		SchemaVersion:      SnapshotSchemaVersion,
		ResourceType:       kind.name,
		Organization:       organization,
		Subject:            subject,
		PermissionGen:      subjectPermissionGen(user),
		Filter:             query.filterCanon,
		SortBy:             query.sortByCanon,
		SortOrder:          query.sortOrder,
		Attributes:         query.includeRaw,
		ExcludedAttributes: query.excludeRaw,
		CreatedAt:          now,
		ExpiresAt:          now.Add(manager.cfg.ttl),
	}

	// The count, ordering and values are materialized in one read transaction; only
	// afterwards does the short-lived transaction end and the sealed artifact begin.
	if kind.name == "User" {
		total, users, err := object.GetScimSnapshotUsers(organization, cond, query.sortColumn, query.descending)
		if err != nil {
			return scim.Page{}, true, err
		}
		envelope.TotalResults = int(total)
		envelope.Resources = make([]scim.Resource, 0, len(users))
		for _, frozenUser := range users {
			resource := user2resource(frozenUser)
			resource.Attributes = projectAttributes(resource.Attributes, query.include, query.exclude)
			envelope.Resources = append(envelope.Resources, *resource)
		}
	} else {
		total, groups, err := object.GetScimSnapshotGroups(organization, cond, query.sortColumn, query.descending)
		if err != nil {
			return scim.Page{}, true, err
		}
		envelope.TotalResults = int(total)
		envelope.Resources = make([]scim.Resource, 0, len(groups))
		for _, frozenGroup := range groups {
			members, err := object.GetGroupUsers(frozenGroup.GetId())
			if err != nil {
				return scim.Page{}, true, err
			}
			resource := group2resource(frozenGroup, members)
			resource.Attributes = projectAttributes(resource.Attributes, query.include, query.exclude)
			envelope.Resources = append(envelope.Resources, *resource)
		}
	}

	token, err := manager.create(envelope)
	if err != nil {
		return scim.Page{}, true, err
	}
	if sink := getHeaderSink(r); sink != nil {
		sink.Add(SnapshotTokenHeader, token)
	}
	return pageFromFrozen(envelope.Resources, envelope.TotalResults, params.StartIndex, params.Count), true, nil
}

func consumeSnapshot(
	r *http.Request,
	manager *snapshotManager,
	query *snapshotQuery,
	params scim.ListRequestParams,
	organization, subject string,
	kind snapshotKind,
) (scim.Page, bool, error) {
	entry, release, err := manager.acquire(query.token)
	if err != nil {
		return scim.Page{}, true, err
	}
	defer release()

	envelope, err := manager.read(entry)
	if err != nil {
		return scim.Page{}, true, err
	}

	if envelope.ResourceType != kind.name ||
		envelope.Organization != organization ||
		envelope.Subject != subject ||
		envelope.Filter != query.filterCanon ||
		envelope.SortBy != query.sortByCanon ||
		envelope.SortOrder != query.sortOrder ||
		!slices.Equal(envelope.Attributes, query.includeRaw) ||
		!slices.Equal(envelope.ExcludedAttributes, query.excludeRaw) {
		return scim.Page{}, true, ErrSnapshotBindingMismatch
	}
	if err = validateSnapshotSubject(r, organization, subject, envelope.PermissionGen); err != nil {
		return scim.Page{}, true, err
	}
	return pageFromFrozen(envelope.Resources, envelope.TotalResults, params.StartIndex, params.Count), true, nil
}

// pageFromFrozen paginates the sealed slice. The offset is derived server-side from
// startIndex against the frozen ordering, never accepted as a client side credential.
func pageFromFrozen(resources []scim.Resource, total, startIndex, count int) scim.Page {
	page := scim.Page{TotalResults: total}
	if count == 0 {
		// count=0 still reports the fixed TotalResults captured at freeze time.
		return page
	}
	if startIndex < 1 {
		startIndex = 1
	}
	offset := startIndex - 1
	if offset >= len(resources) {
		page.Resources = []scim.Resource{}
		return page
	}
	end := offset + count
	if end > len(resources) {
		end = len(resources)
	}
	page.Resources = resources[offset:end]
	return page
}

// HandleSnapshotRelease serves GET ...?snapshot=release&snapshotToken=... before the
// SCIM library takes over, returning 204 on success or a serialized SCIM error.
func HandleSnapshotRelease(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.URL.Query().Get(snapshotQueryMode)) != snapshotModeRelease {
		return false
	}
	manager := getSnapshotManager()
	subject, err := getSubject(r)
	if err == nil {
		if manager == nil {
			err = ErrSnapshotTokenInvalid
		} else if token := snapshotTokenFromRequest(r); token != "" {
			err = manager.release(token, subject)
		} else {
			err = ErrSnapshotTokenInvalid
		}
	}
	if err != nil {
		writeSnapshotError(w, err)
		return true
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusNoContent)
	return true
}

func writeSnapshotError(w http.ResponseWriter, err error) {
	scimErr, ok := err.(scimerrors.ScimError)
	if !ok {
		scimErr = scimerrors.ScimError{Detail: err.Error(), Status: http.StatusInternalServerError}
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(scimErr.Status)
	_ = json.NewEncoder(w).Encode(scimErr)
}
