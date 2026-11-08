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
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/elimity-com/scim"
	"github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/schema"
	"github.com/scim2/filter-parser/v2"
)

const (
	// BulkMaxOperations is the maximum number of operations accepted in one bulk request.
	BulkMaxOperations = 100
	// BulkMaxPayloadSize is the maximum accepted bulk request body size in bytes.
	BulkMaxPayloadSize = 1 << 20
	// BulkMaxReferenceDepth bounds the nesting depth while walking operation data, so
	// pathological payloads cannot exhaust the stack while resolving references.
	BulkMaxReferenceDepth = 10
	// BulkExecutionTimeout bounds the time spent processing a single bulk request.
	BulkExecutionTimeout = 30 * time.Second

	bulkRequestSchema  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	bulkResponseSchema = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	patchOpSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	bulkIDPrefix       = "bulkId:"
)

// bulkReferenceAttributes lists the only attributes in which a "bulkId:..." value is
// resolved as a transient reference to another operation. It mirrors the resource
// schemas declared in server.go: the User schema has no inter-resource references,
// a Group references users only through members[].value.
var bulkReferenceAttributes = map[string]map[string]bool{
	"Group": {"members.value": true},
}

// bulkContextHook and bulkStepHook make cancellation tests deterministic; production
// code leaves them nil.
var (
	bulkContextHook func(parent context.Context) (context.Context, context.CancelFunc)
	bulkStepHook    func(operationIndex int)
)

type bulkRequestBody struct {
	Schemas      []string        `json:"schemas"`
	FailOnErrors int             `json:"failOnErrors"`
	Operations   []bulkRequestOp `json:"Operations"`
}

type bulkRequestOp struct {
	Method  string          `json:"method"`
	BulkID  string          `json:"bulkId,omitempty"`
	Path    string          `json:"path"`
	Data    json.RawMessage `json:"data,omitempty"`
	Version string          `json:"version,omitempty"`
}

type bulkResponseBody struct {
	Schemas    []string       `json:"schemas"`
	Operations []bulkResponse `json:"Operations"`
}

type bulkResponse struct {
	Method   string          `json:"method"`
	BulkID   string          `json:"bulkId,omitempty"`
	Path     string          `json:"path,omitempty"`
	Location string          `json:"location,omitempty"`
	Status   string          `json:"status"`
	Response json.RawMessage `json:"response,omitempty"`
}

// bulkPlannedOp is a request operation together with its pre-parse result. A non-nil
// scimErr means the operation is invalid and is never dispatched.
type bulkPlannedOp struct {
	index      int
	req        bulkRequestOp
	rtName     string
	endpoint   string
	itemID     string
	collection bool
	deps       map[string]bool
	scimErr    *errors.ScimError
}

// ServeBulkHTTP implements RFC 7644 section 3.7. Each operation is an independent
// transaction: confirmed operations are never rolled back or replayed, and the response
// keeps one entry per requested operation, in the original order.
func ServeBulkHTTP(w http.ResponseWriter, r *http.Request) {
	organization, err := getOrganization(r)
	if err != nil {
		if scimErr, ok := err.(errors.ScimError); ok {
			writeBulkScimError(w, scimErr)
		} else {
			writeBulkScimError(w, errors.ScimError{Detail: err.Error(), Status: http.StatusInternalServerError})
		}
		return
	}

	body, scimErr := readBulkBody(r)
	if scimErr != nil {
		writeBulkScimError(w, *scimErr)
		return
	}

	var request bulkRequestBody
	if err := json.Unmarshal(body, &request); err != nil {
		writeBulkScimError(w, errors.ScimErrorInvalidSyntax)
		return
	}
	if !containsString(request.Schemas, bulkRequestSchema) {
		writeBulkScimError(w, errors.ScimError{
			ScimType: errors.ScimTypeInvalidValue,
			Detail:   fmt.Sprintf("the bulk request must use the schema: %s", bulkRequestSchema),
			Status:   http.StatusBadRequest,
		})
		return
	}
	if len(request.Operations) == 0 {
		writeBulkScimError(w, errors.ScimError{
			ScimType: errors.ScimTypeInvalidValue,
			Detail:   "the bulk request must contain at least one operation",
			Status:   http.StatusBadRequest,
		})
		return
	}
	if len(request.Operations) > BulkMaxOperations {
		writeBulkScimError(w, errors.ScimError{
			ScimType: errors.ScimTypeTooMany,
			Detail:   fmt.Sprintf("a bulk request accepts at most %d operations", BulkMaxOperations),
			Status:   http.StatusRequestEntityTooLarge,
		})
		return
	}

	planned := planBulkOperations(request.Operations, organization)
	markDuplicateBulkIDs(planned)
	validateBulkReferences(planned)
	order := scheduleBulkOperations(planned)

	ctx := r.Context()
	cancel := func() {}
	if bulkContextHook != nil {
		ctx, cancel = bulkContextHook(ctx)
	} else {
		ctx, cancel = context.WithTimeout(ctx, BulkExecutionTimeout)
	}
	defer cancel()

	responses := executeBulkOperations(r, ctx, planned, order, request.FailOnErrors)

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(bulkResponseBody{
		Schemas:    []string{bulkResponseSchema},
		Operations: responses,
	})
}

func readBulkBody(r *http.Request) ([]byte, *errors.ScimError) {
	if r.ContentLength > BulkMaxPayloadSize {
		return nil, bulkTooLargeError()
	}

	var body bytes.Buffer
	if _, err := io.Copy(&body, http.MaxBytesReader(nil, r.Body, BulkMaxPayloadSize)); err != nil {
		var maxBytesErr *http.MaxBytesError
		if asMaxBytesError(err, &maxBytesErr) {
			return nil, bulkTooLargeError()
		}
		return nil, &errors.ScimError{Detail: err.Error(), Status: http.StatusBadRequest}
	}
	return body.Bytes(), nil
}

func bulkTooLargeError() *errors.ScimError {
	return &errors.ScimError{
		ScimType: errors.ScimTypeTooMany,
		Detail:   fmt.Sprintf("the bulk payload exceeds the limit of %d bytes", BulkMaxPayloadSize),
		Status:   http.StatusRequestEntityTooLarge,
	}
}

func asMaxBytesError(err error, target **http.MaxBytesError) bool {
	for err != nil {
		if e, ok := err.(*http.MaxBytesError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// planBulkOperations validates the method, path and schema of every operation and
// collects the transient references it declares.
func planBulkOperations(ops []bulkRequestOp, organization string) []*bulkPlannedOp {
	planned := make([]*bulkPlannedOp, len(ops))
	bulkIDs := make(map[string]int)

	for i, op := range ops {
		p := &bulkPlannedOp{index: i, req: op, deps: map[string]bool{}}
		planned[i] = p

		if op.Method != http.MethodPost && op.Method != http.MethodPut &&
			op.Method != http.MethodPatch && op.Method != http.MethodDelete {
			p.scimErr = bulkBadRequest(errors.ScimTypeInvalidSyntax,
				fmt.Sprintf("the bulk operation method: %q is not supported", op.Method))
			continue
		}

		endpoint, itemID, collection, ok := parseBulkPath(op.Path)
		if !ok {
			p.scimErr = bulkBadRequest(errors.ScimTypeInvalidPath,
				fmt.Sprintf("the bulk operation path: %q does not target /Users or /Groups", op.Path))
			continue
		}
		p.endpoint = endpoint
		p.itemID = itemID
		p.collection = collection
		p.rtName = resourceTypeOf(endpoint)

		if op.BulkID != "" {
			if first, dup := bulkIDs[op.BulkID]; dup {
				p.scimErr = bulkBadRequest(errors.ScimTypeInvalidSyntax,
					fmt.Sprintf("the bulkId: %q is duplicated, it was first used by operation %d", op.BulkID, first))
				continue
			}
			bulkIDs[op.BulkID] = i
		}
		if op.Method == http.MethodPost && op.BulkID == "" {
			p.scimErr = bulkBadRequest(errors.ScimTypeInvalidValue,
				"a POST bulk operation must carry a bulkId")
			continue
		}
		if op.Method == http.MethodPost && !collection {
			p.scimErr = bulkBadRequest(errors.ScimTypeInvalidPath,
				fmt.Sprintf("the POST method only supports the collection endpoint: %s", endpoint))
			continue
		}
		if op.Method != http.MethodPost && collection {
			p.scimErr = bulkBadRequest(errors.ScimTypeInvalidPath,
				fmt.Sprintf("the %s method requires a resource id in the path: %s", op.Method, op.Path))
			continue
		}

		if scimErr := planBulkData(p, op, organization); scimErr != nil {
			p.scimErr = scimErr
			continue
		}
		if scimErr := p.extractReferences(); scimErr != nil {
			p.scimErr = scimErr
		}
	}
	return planned
}

func planBulkData(p *bulkPlannedOp, op bulkRequestOp, organization string) *errors.ScimError {
	switch op.Method {
	case http.MethodDelete:
		return nil
	case http.MethodPost, http.MethodPut:
		if len(bytes.TrimSpace(op.Data)) == 0 {
			return bulkBadRequest(errors.ScimTypeInvalidValue,
				fmt.Sprintf("the %s operation on %s requires a resource body", op.Method, op.Path))
		}
		rt := findResourceType(p.rtName)
		if rt == nil {
			return bulkBadRequest(errors.ScimTypeInvalidPath, "unknown resource type")
		}
		if scimErr := validateBulkResource(*rt, op.Data); scimErr != nil {
			return scimErr
		}
		return checkBulkOrganization(p, op.Data, organization)
	case http.MethodPatch:
		return validateBulkPatch(op.Data)
	default:
		return nil
	}
}

// validateBulkResource mirrors the resource validation the library runs for single
// resource POST/PUT requests, including the common externalId attribute and extensions.
func validateBulkResource(rt scim.ResourceType, raw []byte) *errors.ScimError {
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return &errors.ScimErrorInvalidSyntax
	}

	attrs := make([]schema.CoreAttribute, 0, len(rt.Schema.Attributes)+1)
	attrs = append(attrs, rt.Schema.Attributes...)
	attrs = append(attrs, schema.SimpleCoreAttribute(schema.SimpleStringParams(schema.StringParams{
		CaseExact:  true,
		Mutability: schema.AttributeMutabilityReadWrite(),
		Name:       schema.CommonAttributeExternalID,
		Uniqueness: schema.AttributeUniquenessNone(),
		Returned:   schema.AttributeReturnedDefault(),
	})))
	coreSchema := rt.Schema
	coreSchema.Attributes = attrs
	if _, scimErr := coreSchema.Validate(data); scimErr != nil {
		return scimErr
	}

	for _, extension := range rt.SchemaExtensions {
		extensionField := data[extension.Schema.ID]
		if extensionField == nil {
			if extension.Required {
				return &errors.ScimErrorInvalidValue
			}
			continue
		}
		if _, scimErr := extension.Schema.Validate(extensionField); scimErr != nil {
			return scimErr
		}
	}
	return nil
}

// checkBulkOrganization rejects bodies naming an organization outside the scope of the
// authenticated request before any write is attempted. An empty scope is the global
// admin scope and may address every organization.
func checkBulkOrganization(p *bulkPlannedOp, raw []byte, organization string) *errors.ScimError {
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return &errors.ScimErrorInvalidSyntax
	}
	extensionKey := UserExtensionKey
	if p.rtName == "Group" {
		extensionKey = GroupExtensionKey
	}
	extension, ok := data[extensionKey].(map[string]interface{})
	if !ok {
		return nil
	}
	owner, _ := extension["organization"].(string)
	if owner == "" || organization == "" || organization == owner {
		return nil
	}
	return &errors.ScimError{
		Detail: "the organization: " + owner + " is not allowed",
		Status: http.StatusForbidden,
	}
}

func validateBulkPatch(raw []byte) *errors.ScimError {
	var patch struct {
		Schemas    []string          `json:"schemas"`
		Operations []json.RawMessage `json:"Operations"`
	}
	if err := json.Unmarshal(raw, &patch); err != nil {
		return &errors.ScimErrorInvalidSyntax
	}
	if len(patch.Schemas) != 1 || patch.Schemas[0] != patchOpSchema {
		return bulkBadRequest(errors.ScimTypeInvalidValue,
			"a PATCH body must use the schema: "+patchOpSchema)
	}
	if len(patch.Operations) == 0 {
		return bulkBadRequest(errors.ScimTypeInvalidValue,
			"a PATCH body must contain at least one operation")
	}
	for _, rawOp := range patch.Operations {
		var patchOp map[string]interface{}
		if err := json.Unmarshal(rawOp, &patchOp); err != nil {
			return &errors.ScimErrorInvalidSyntax
		}
		op, _ := patchOp["op"].(string)
		if op != scim.PatchOperationAdd && op != scim.PatchOperationReplace && op != scim.PatchOperationRemove {
			return bulkBadRequest(errors.ScimTypeInvalidValue,
				fmt.Sprintf("the patch operation: %q is not supported", op))
		}
		pathStr, hasPath := patchOp["path"].(string)
		if op == scim.PatchOperationRemove && !hasPath {
			return bulkBadRequest(errors.ScimTypeInvalidPath, "a remove patch operation requires a path")
		}
		if hasPath {
			if _, err := filter.ParsePath([]byte(pathStr)); err != nil {
				return &errors.ScimErrorInvalidPath
			}
		}
		if op != scim.PatchOperationRemove {
			if _, ok := patchOp["value"]; !ok {
				return bulkBadRequest(errors.ScimTypeInvalidValue,
					fmt.Sprintf("the %s patch operation requires a value", op))
			}
		}
	}
	return nil
}

// parseBulkPath splits a bulk operation path into the resource endpoint and the optional
// resource id. The leading /v2 version segment is optional.
func parseBulkPath(rawPath string) (endpoint, itemID string, collection, ok bool) {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return "", "", false, false
	}
	path = strings.TrimPrefix(path, "/v2")
	for _, candidate := range []string{"/Users", "/Groups"} {
		if path == candidate {
			return candidate, "", true, true
		}
		if strings.HasPrefix(path, candidate+"/") {
			rest := strings.TrimPrefix(path, candidate+"/")
			// A raw slash would be a sub-path. Casdoor resource ids are "owner/name"
			// and arrive percent-encoded, so an escaped slash inside the single segment
			// is part of the id.
			if strings.Contains(rest, "/") {
				return "", "", false, false
			}
			id, err := url.PathUnescape(rest)
			if err != nil || id == "" {
				return "", "", false, false
			}
			return candidate, id, false, true
		}
	}
	return "", "", false, false
}

func resourceTypeOf(endpoint string) string {
	switch endpoint {
	case "/Users":
		return "User"
	case "/Groups":
		return "Group"
	default:
		return ""
	}
}

func findResourceType(name string) *scim.ResourceType {
	for i := range Server.ResourceTypes {
		if Server.ResourceTypes[i].Name == name {
			return &Server.ResourceTypes[i]
		}
	}
	return nil
}

// extractReferences collects the bulkId dependencies of the operation. References are
// only read from the reference attributes declared for the resource type and from the
// resource id segment of item paths; other string values are left untouched.
func (p *bulkPlannedOp) extractReferences() *errors.ScimError {
	if strings.HasPrefix(p.itemID, bulkIDPrefix) {
		p.deps[strings.TrimPrefix(p.itemID, bulkIDPrefix)] = true
	}

	if p.rtName != "Group" || len(p.req.Data) == 0 {
		return nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(p.req.Data, &data); err != nil {
		return &errors.ScimErrorInvalidSyntax
	}
	if err := checkBulkJSONDepth(data, 1); err != nil {
		return err
	}

	if !bulkReferenceAttributes[p.rtName]["members.value"] {
		return nil
	}
	switch p.req.Method {
	case http.MethodPost, http.MethodPut:
		for _, bulkID := range memberBulkIDs(data["members"]) {
			p.deps[bulkID] = true
		}
	case http.MethodPatch:
		for _, ref := range patchMemberBulkIDs(data) {
			p.deps[ref] = true
		}
	}
	return nil
}

func checkBulkJSONDepth(value interface{}, depth int) *errors.ScimError {
	if depth > BulkMaxReferenceDepth {
		return bulkBadRequest(errors.ScimTypeInvalidValue,
			fmt.Sprintf("the bulk operation data exceeds the reference depth limit of %d", BulkMaxReferenceDepth))
	}
	switch v := value.(type) {
	case map[string]interface{}:
		for _, child := range v {
			if err := checkBulkJSONDepth(child, depth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range v {
			if err := checkBulkJSONDepth(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func memberBulkIDs(raw interface{}) []string {
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	ids := make([]string, 0)
	for _, item := range arr {
		member, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		value, ok := member["value"].(string)
		if ok && strings.HasPrefix(value, bulkIDPrefix) {
			ids = append(ids, strings.TrimPrefix(value, bulkIDPrefix))
		}
	}
	return ids
}

func patchMemberBulkIDs(patchBody map[string]interface{}) []string {
	rawOps, ok := patchBody["Operations"].([]interface{})
	if !ok {
		return nil
	}
	ids := make([]string, 0)
	for _, rawOp := range rawOps {
		patchOp, ok := rawOp.(map[string]interface{})
		if !ok {
			continue
		}
		pathStr, _ := patchOp["path"].(string)
		if pathStr != "" {
			parsed, err := filter.ParsePath([]byte(pathStr))
			if err == nil && strings.EqualFold(parsed.AttributePath.AttributeName, "members") {
				if attr, ok := parsed.ValueExpression.(*filter.AttributeExpression); ok {
					if value, ok := attr.CompareValue.(string); ok && strings.HasPrefix(value, bulkIDPrefix) {
						ids = append(ids, strings.TrimPrefix(value, bulkIDPrefix))
					}
				}
			}
		}
		switch value := patchOp["value"].(type) {
		case []interface{}:
			ids = append(ids, memberBulkIDs(value)...)
		case map[string]interface{}:
			ids = append(ids, memberBulkIDs(value["members"])...)
		}
	}
	return ids
}

// validateBulkReferences turns undefined, non-creatable and circular references into
// per-operation errors.
func validateBulkReferences(planned []*bulkPlannedOp) {
	byBulkID := map[string]*bulkPlannedOp{}
	for _, p := range planned {
		if p.scimErr == nil && p.req.BulkID != "" {
			byBulkID[p.req.BulkID] = p
		}
	}

	for _, p := range planned {
		if p.scimErr != nil {
			continue
		}
		for bulkID := range p.deps {
			if _, ok := byBulkID[bulkID]; !ok {
				p.scimErr = bulkBadRequest(errors.ScimTypeInvalidValue,
					fmt.Sprintf("the bulkId reference: %q is not defined by an operation in this request", bulkID))
				break
			}
		}
	}

	const (
		unvisited = iota
		visiting
		visited
	)
	color := map[int]int{}
	var visit func(p *bulkPlannedOp) bool
	visit = func(p *bulkPlannedOp) bool {
		color[p.index] = visiting
		cyclic := false
		for bulkID := range p.deps {
			target, ok := byBulkID[bulkID]
			if !ok || target.scimErr != nil {
				continue
			}
			switch color[target.index] {
			case unvisited:
				if visit(target) {
					cyclic = true
				}
			case visiting:
				target.scimErr = bulkBadRequest(errors.ScimTypeInvalidValue,
					fmt.Sprintf("the bulkId: %q is part of a circular reference", target.req.BulkID))
				cyclic = true
			}
		}
		color[p.index] = visited
		if cyclic && p.scimErr == nil {
			p.scimErr = bulkBadRequest(errors.ScimTypeInvalidValue,
				fmt.Sprintf("the bulkId: %q is part of a circular reference", p.req.BulkID))
		}
		return cyclic
	}
	for _, p := range planned {
		if p.scimErr == nil && color[p.index] == unvisited {
			visit(p)
		}
	}

	// A reference to an operation that can never complete makes the dependent
	// operation unexecutable as well.
	changed := true
	for changed {
		changed = false
		for _, p := range planned {
			if p.scimErr != nil {
				continue
			}
			for bulkID := range p.deps {
				target, ok := byBulkID[bulkID]
				if ok && target.scimErr != nil {
					p.scimErr = bulkBadRequest(errors.ScimTypeInvalidValue,
						fmt.Sprintf("the bulkId reference: %q cannot be resolved", bulkID))
					changed = true
					break
				}
			}
		}
	}
}

// markDuplicateBulkIDs rejects every operation carrying a bulkId that is not unique in
// the request: a duplicated transient id makes both the resource identity and its
// references ambiguous.
func markDuplicateBulkIDs(planned []*bulkPlannedOp) {
	count := map[string]int{}
	for _, p := range planned {
		if p.req.BulkID != "" {
			count[p.req.BulkID]++
		}
	}
	for _, p := range planned {
		if p.scimErr == nil && p.req.BulkID != "" && count[p.req.BulkID] > 1 {
			p.scimErr = bulkBadRequest(errors.ScimTypeInvalidSyntax,
				fmt.Sprintf("the bulkId: %q is duplicated in the bulk request", p.req.BulkID))
		}
	}
}

// scheduleBulkOperations returns every operation in processing order. Referenced
// operations run first, invalid operations keep their request position, and the request
// order breaks every tie, so failOnErrors is counted where each operation is encountered.
func scheduleBulkOperations(planned []*bulkPlannedOp) []*bulkPlannedOp {
	validByBulkID := map[string]*bulkPlannedOp{}
	for _, p := range planned {
		if p.scimErr == nil && p.req.BulkID != "" {
			validByBulkID[p.req.BulkID] = p
		}
	}
	indegree := map[int]int{}
	for _, p := range planned {
		if p.scimErr != nil {
			continue
		}
		for bulkID := range p.deps {
			if _, ok := validByBulkID[bulkID]; ok {
				indegree[p.index]++
			}
		}
	}

	order := make([]*bulkPlannedOp, 0, len(planned))
	done := map[int]bool{}
	for len(order) < len(planned) {
		progressed := false
		for _, p := range planned {
			if done[p.index] || indegree[p.index] > 0 {
				continue
			}
			done[p.index] = true
			order = append(order, p)
			progressed = true
			if p.scimErr != nil || p.req.BulkID == "" {
				continue
			}
			for _, dependent := range planned {
				if dependent.scimErr == nil && dependent.deps[p.req.BulkID] {
					indegree[dependent.index]--
				}
			}
		}
		if !progressed {
			// Defensive: validateBulkReferences should have marked every cycle already.
			for _, p := range planned {
				if !done[p.index] {
					p.scimErr = bulkBadRequest(errors.ScimTypeInvalidValue, "unresolvable bulkId reference")
					done[p.index] = true
					order = append(order, p)
				}
			}
		}
	}
	return order
}

func executeBulkOperations(r *http.Request, ctx context.Context, planned []*bulkPlannedOp,
	order []*bulkPlannedOp, failOnErrors int,
) []bulkResponse {
	results := make([]bulkResponse, len(planned))
	idMap := map[string]string{}
	errorCount := 0
	stopped := false

	for _, p := range order {
		if bulkStepHook != nil {
			bulkStepHook(p.index)
		}

		if stopped {
			results[p.index] = notProcessedBulkResponse(p, notProcessedError(failOnErrors, ctx))
			continue
		}
		if err := ctx.Err(); err != nil {
			stopped = true
			results[p.index] = notProcessedBulkResponse(p, canceledBulkError(err))
			continue
		}
		if failOnErrors > 0 && errorCount >= failOnErrors {
			stopped = true
			results[p.index] = notProcessedBulkResponse(p, thresholdBulkError(failOnErrors))
			continue
		}

		// Pre-parse failures are counted at their position in the processing order, the
		// same way runtime failures of dispatched operations are.
		if p.scimErr != nil {
			errorCount++
			results[p.index] = errorBulkResponse(p, *p.scimErr)
			continue
		}

		target, body, scimErr := resolveBulkOperation(p, idMap)
		if scimErr != nil {
			errorCount++
			results[p.index] = errorBulkResponse(p, *scimErr)
			continue
		}

		status, responseBody := dispatchBulkOperation(r, p.req.Method, target, body)
		entry := bulkResponse{
			Method: p.req.Method,
			BulkID: p.req.BulkID,
			Path:   p.req.Path,
			Status: fmt.Sprintf("%d", status),
		}
		if len(responseBody) > 0 {
			entry.Response = json.RawMessage(responseBody)
		}
		if status < http.StatusBadRequest {
			if p.req.BulkID != "" {
				if id := resourceIDOf(responseBody); id != "" {
					idMap[p.req.BulkID] = id
				}
			}
			entry.Location = bulkLocation(r, p, target, responseBody)
			recordBulkChange(r, p, status, responseBody)
		} else {
			errorCount++
		}
		results[p.index] = entry
	}
	return results
}

// resolveBulkOperation substitutes transient bulkId references with the real resource
// ids. Only reference attributes and the id segment of item paths are rewritten; any
// other string, including one that happens to contain the "bulkId:" prefix, is kept.
func resolveBulkOperation(p *bulkPlannedOp, idMap map[string]string) (string, []byte, *errors.ScimError) {
	target := p.req.Path
	if strings.HasPrefix(p.itemID, bulkIDPrefix) {
		bulkID := strings.TrimPrefix(p.itemID, bulkIDPrefix)
		realID, ok := idMap[bulkID]
		if !ok {
			return "", nil, bulkBadRequest(errors.ScimTypeInvalidValue,
				fmt.Sprintf("the bulkId reference: %q cannot be resolved", bulkID))
		}
		target = p.endpoint + "/" + url.PathEscape(realID)
	}

	if len(p.req.Data) == 0 || p.rtName != "Group" {
		return target, p.req.Data, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(p.req.Data, &data); err != nil {
		return "", nil, &errors.ScimErrorInvalidSyntax
	}

	switch p.req.Method {
	case http.MethodPost, http.MethodPut:
		if members, ok := data["members"].([]interface{}); ok {
			data["members"] = resolveMembers(members, idMap)
		}
	case http.MethodPatch:
		resolvePatchMembers(data, idMap)
	}

	body, err := json.Marshal(data)
	if err != nil {
		return "", nil, &errors.ScimErrorInternal
	}
	return target, body, nil
}

func resolveMembers(members []interface{}, idMap map[string]string) []interface{} {
	for _, item := range members {
		member, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		value, ok := member["value"].(string)
		if !ok || !strings.HasPrefix(value, bulkIDPrefix) {
			continue
		}
		if realID, ok := idMap[strings.TrimPrefix(value, bulkIDPrefix)]; ok {
			member["value"] = realID
		}
	}
	return members
}

func resolvePatchMembers(patchBody map[string]interface{}, idMap map[string]string) {
	rawOps, ok := patchBody["Operations"].([]interface{})
	if !ok {
		return
	}
	for _, rawOp := range rawOps {
		patchOp, ok := rawOp.(map[string]interface{})
		if !ok {
			continue
		}
		if pathStr, ok := patchOp["path"].(string); ok {
			parsed, err := filter.ParsePath([]byte(pathStr))
			if err == nil && strings.EqualFold(parsed.AttributePath.AttributeName, "members") {
				if attr, ok := parsed.ValueExpression.(*filter.AttributeExpression); ok {
					if value, ok := attr.CompareValue.(string); ok && strings.HasPrefix(value, bulkIDPrefix) {
						if realID, ok := idMap[strings.TrimPrefix(value, bulkIDPrefix)]; ok {
							attr.CompareValue = realID
							patchOp["path"] = parsed.String()
						}
					}
				}
			}
		}
		switch value := patchOp["value"].(type) {
		case []interface{}:
			patchOp["value"] = resolveMembers(value, idMap)
		case map[string]interface{}:
			if members, ok := value["members"].([]interface{}); ok {
				value["members"] = resolveMembers(members, idMap)
			}
		}
	}
}

// dispatchBulkOperation runs one operation through the same SCIM server and handlers as
// single-resource requests, so schema validation, scope checks and resource logic are
// never duplicated or bypassed.
func dispatchBulkOperation(orig *http.Request, method, target string, body []byte) (int, []byte) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/scim+json")
	if language := orig.Header.Get("Accept-Language"); language != "" {
		req.Header.Set("Accept-Language", language)
	}
	organization, _ := getOrganization(orig)
	req = WithOrganization(req, organization)

	recorder := httptest.NewRecorder()
	Server.ServeHTTP(recorder, req)
	return recorder.Code, recorder.Body.Bytes()
}

func resourceIDOf(raw []byte) string {
	var resource struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &resource); err != nil {
		return ""
	}
	return resource.ID
}

func bulkLocation(r *http.Request, p *bulkPlannedOp, target string, raw []byte) string {
	base := strings.TrimSuffix(r.URL.Path, "/Bulk")
	var resource struct {
		Meta struct {
			Location string `json:"location"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &resource); err == nil && resource.Meta.Location != "" {
		return base + "/" + resource.Meta.Location
	}
	if p.collection {
		return ""
	}
	return base + target
}

// recordBulkChange writes the audit record of a confirmed operation, which is also what
// fires the matching webhooks. Failed and not-started operations never reach this point.
func recordBulkChange(r *http.Request, p *bulkPlannedOp, status int, responseBody []byte) {
	defer func() {
		_ = recover()
	}()

	organization, _ := getOrganization(r)
	if organization == "" {
		organization = organizationOfResource(p.rtName, responseBody)
	}
	record := &object.Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: organization,
		ClientIp:     r.RemoteAddr,
		Method:       p.req.Method,
		RequestUri:   p.req.Path,
		Action:       bulkRecordAction(p.rtName, p.req.Method),
		Object:       string(responseBody),
		StatusCode:   status,
	}
	object.AddRecord(record)
}

func bulkRecordAction(resourceType, method string) string {
	resource := "user"
	if resourceType == "Group" {
		resource = "group"
	}
	switch method {
	case http.MethodPost:
		return "scim-add-" + resource
	case http.MethodDelete:
		return "scim-delete-" + resource
	default:
		return "scim-update-" + resource
	}
}

func organizationOfResource(resourceType string, raw []byte) string {
	extensionKey := UserExtensionKey
	if resourceType == "Group" {
		extensionKey = GroupExtensionKey
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return ""
	}
	extension, ok := data[extensionKey].(map[string]interface{})
	if !ok {
		return ""
	}
	owner, _ := extension["organization"].(string)
	return owner
}

func errorBulkResponse(p *bulkPlannedOp, scimErr errors.ScimError) bulkResponse {
	raw, _ := json.Marshal(scimErr)
	return bulkResponse{
		Method:   p.req.Method,
		BulkID:   p.req.BulkID,
		Path:     p.req.Path,
		Status:   fmt.Sprintf("%d", scimErr.Status),
		Response: raw,
	}
}

func notProcessedBulkResponse(p *bulkPlannedOp, scimErr errors.ScimError) bulkResponse {
	return errorBulkResponse(p, scimErr)
}

func thresholdBulkError(failOnErrors int) errors.ScimError {
	return errors.ScimError{
		Detail: fmt.Sprintf("the operation was not processed because the failOnErrors threshold of %d was reached", failOnErrors),
		Status: http.StatusBadRequest,
	}
}

func canceledBulkError(err error) errors.ScimError {
	return errors.ScimError{
		Detail: "the bulk request was canceled or timed out before the operation was processed: " + err.Error(),
		Status: http.StatusServiceUnavailable,
	}
}

func notProcessedError(failOnErrors int, ctx context.Context) errors.ScimError {
	if err := ctx.Err(); err != nil {
		return canceledBulkError(err)
	}
	return thresholdBulkError(failOnErrors)
}

func bulkBadRequest(scimType errors.ScimType, detail string) *errors.ScimError {
	return &errors.ScimError{ScimType: scimType, Detail: detail, Status: http.StatusBadRequest}
}

func writeBulkScimError(w http.ResponseWriter, scimErr errors.ScimError) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(scimErr.Status)
	_ = json.NewEncoder(w).Encode(scimErr)
}

func containsString(arr []string, target string) bool {
	for _, item := range arr {
		if item == target {
			return true
		}
	}
	return false
}
