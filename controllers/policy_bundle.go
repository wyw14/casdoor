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

package controllers

import (
	"encoding/json"

	"github.com/casdoor/casdoor/object"
)

// PlanPolicyBundle
// @Title PlanPolicyBundle
// @Tag Policy Bundle API
// @Description build the isolated candidate configuration, validate it with real Casbin enforcers and run the regression corpus without writing anything
// @Param   body    body   object.PolicyBundle  true        "The limited set of role, group and permission changes"
// @Success 200 {object} object.PolicyBundlePlanResult The Response object
// @router /plan-policy-bundle [post]
func (c *ApiController) PlanPolicyBundle() {
	var bundle object.PolicyBundle
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &bundle)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !c.requireOrganizationPermission(bundle.Owner) {
		return
	}

	result, err := object.PlanPolicyBundle(&bundle)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(result)
}

// PublishPolicyBundle
// @Title PublishPolicyBundle
// @Tag Policy Bundle API
// @Description re-validate the planned bundle and atomically commit one generation, including the configuration rows, the Casbin rule changes and the generation pointer
// @Param   digest    query    string  false        "The digest returned by the plan endpoint"
// @Param   body    body   object.PolicyBundle  true        "The limited set of role, group and permission changes"
// @Success 200 {object} object.PolicyBundlePublishResult The Response object
// @router /publish-policy-bundle [post]
func (c *ApiController) PublishPolicyBundle() {
	digest := c.Ctx.Input.Query("digest")

	var bundle object.PolicyBundle
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &bundle)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !c.requireOrganizationPermission(bundle.Owner) {
		return
	}

	result, err := object.PublishPolicyBundle(&bundle, digest)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(result)
}

// GetPolicyBundleGenerations
// @Title GetPolicyBundleGenerations
// @Tag Policy Bundle API
// @Description get the policy bundle generations of an organization
// @Param   owner     query    string  true        "The owner of the generations"
// @Success 200 {array} object.PolicyBundleGeneration The Response object
// @router /get-policy-bundle-generations [get]
func (c *ApiController) GetPolicyBundleGenerations() {
	owner := c.Ctx.Input.Query("owner")

	generations, err := object.GetPolicyBundleGenerations(owner)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(generations)
}

// GetPolicyBundlePublishStatus
// @Title GetPolicyBundlePublishStatus
// @Tag Policy Bundle API
// @Description query the status of a generation when the commit result is uncertain
// @Param   owner     query    string  true        "The owner of the generation"
// @Param   generation     query    string  false        "The generation name, empty means the current published generation"
// @Success 200 {object} controllers.Response The Response object
// @router /get-policy-bundle-publish-status [get]
func (c *ApiController) GetPolicyBundlePublishStatus() {
	owner := c.Ctx.Input.Query("owner")
	generation := c.Ctx.Input.Query("generation")

	status, generationName, err := object.GetPolicyBundlePublishStatus(owner, generation)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(map[string]string{
		"status":     status,
		"generation": generationName,
	})
}

// BundleEnforce
// @Title BundleEnforce
// @Tag Policy Bundle API
// @Description enforce a request against exactly one published generation view; falls back to the live enforcer when no generation is published
// @Param   owner     query    string  true        "The owner organization"
// @Param   permissionId     query    string  true        "The id (owner/name) of the permission"
// @Param   body    body   []interface{}  true        "The Casbin request"
// @Success 200 {object} controllers.Response The Response object
// @router /bundle-enforce [post]
func (c *ApiController) BundleEnforce() {
	owner := c.Ctx.Input.Query("owner")
	permissionId := c.Ctx.Input.Query("permissionId")

	var request []interface{}
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &request)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	decision, err := object.EnforceWithBundleView(owner, permissionId, request)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if decision != nil {
		c.ResponseOk(decision)
		return
	}

	// No published generation view: keep the legacy per-request live path available.
	permission, err := object.GetPermission(permissionId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if permission == nil {
		c.ResponseError("the permission: " + permissionId + " is not found")
		return
	}

	allowed, err := object.Enforce(permission, request)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(map[string]interface{}{
		"allow":      allowed,
		"generation": "live",
	})
}
