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
	"strings"

	"github.com/elimity-com/scim"
)

// projectAttributes applies the RFC 7644 section 3.4.3 attribute projection before the
// resources enter the sealed artifact. Projection happens on the server side, so an
// excluded attribute is never written to disk in the first place. The structural
// attributes id, externalId, meta and schemas live outside ResourceAttributes and are
// always retained by the SCIM library.
func projectAttributes(attrs scim.ResourceAttributes, include, exclude []attrRequest) scim.ResourceAttributes {
	if len(include) == 0 && len(exclude) == 0 {
		return attrs
	}

	if len(include) > 0 {
		result := make(scim.ResourceAttributes)
		for key, value := range attrs {
			lowerKey := strings.ToLower(key)
			for _, request := range include {
				if request.name != lowerKey {
					continue
				}
				if request.sub == "" {
					result[key] = value
					break
				}
				if projected, ok := projectSubAttribute(value, request.sub); ok {
					result[key] = projected
				}
				break
			}
		}
		return result
	}

	result := make(scim.ResourceAttributes, len(attrs))
	for key, value := range attrs {
		result[key] = value
	}
	for _, request := range exclude {
		key, ok := findAttributeKey(result, request.name)
		if !ok {
			continue
		}
		if request.sub == "" {
			delete(result, key)
			continue
		}
		if projected, ok := excludeSubAttribute(result[key], request.sub); ok {
			result[key] = projected
		}
	}
	return result
}

func findAttributeKey(attrs scim.ResourceAttributes, lowerName string) (string, bool) {
	for key := range attrs {
		if strings.ToLower(key) == lowerName {
			return key, true
		}
	}
	return "", false
}

func asAttributeMap(value interface{}) (map[string]interface{}, bool) {
	switch v := value.(type) {
	case scim.ResourceAttributes:
		return v, true
	case map[string]interface{}:
		return v, true
	default:
		return nil, false
	}
}

func filterMapKeys(value map[string]interface{}, sub string, keep bool) map[string]interface{} {
	result := make(map[string]interface{})
	for key, item := range value {
		matches := strings.ToLower(key) == sub
		if matches == keep {
			result[key] = item
		}
	}
	return result
}

// projectSubAttribute keeps only the requested sub-attribute of a complex attribute or
// every element of a multi-valued complex attribute.
func projectSubAttribute(value interface{}, sub string) (interface{}, bool) {
	if m, ok := asAttributeMap(value); ok {
		return filterMapKeys(m, sub, true), true
	}
	switch items := value.(type) {
	case []scim.ResourceAttributes:
		result := make([]scim.ResourceAttributes, 0, len(items))
		for _, item := range items {
			result = append(result, filterMapKeys(item, sub, true))
		}
		return result, true
	case []interface{}:
		result := make([]interface{}, 0, len(items))
		for _, item := range items {
			if m, ok := asAttributeMap(item); ok {
				result = append(result, filterMapKeys(m, sub, true))
			} else {
				result = append(result, item)
			}
		}
		return result, true
	default:
		return nil, false
	}
}

func excludeSubAttribute(value interface{}, sub string) (interface{}, bool) {
	if m, ok := asAttributeMap(value); ok {
		return filterMapKeys(m, sub, false), true
	}
	switch items := value.(type) {
	case []scim.ResourceAttributes:
		result := make([]scim.ResourceAttributes, 0, len(items))
		for _, item := range items {
			result = append(result, filterMapKeys(item, sub, false))
		}
		return result, true
	case []interface{}:
		result := make([]interface{}, 0, len(items))
		for _, item := range items {
			if m, ok := asAttributeMap(item); ok {
				result = append(result, filterMapKeys(m, sub, false))
			} else {
				result = append(result, item)
			}
		}
		return result, true
	default:
		return nil, false
	}
}
