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
	"context"
	"net/http"
	"sync"

	"github.com/elimity-com/scim/errors"
)

type organizationKey struct{}

type subjectKey struct{}

type headerSinkKey struct{}

// WithOrganization limits the SCIM request to the users and groups of the organization,
// an empty organization (a global admin) to none. A request without it is denied.
func WithOrganization(r *http.Request, organization string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), organizationKey{}, organization))
}

func getOrganization(r *http.Request) (string, error) {
	organization, ok := r.Context().Value(organizationKey{}).(string)
	if !ok {
		return "", errors.ScimError{Detail: "the SCIM request has no organization", Status: http.StatusForbidden}
	}
	return organization, nil
}

// WithSubject binds the authenticated caller id (owner/name) to the request. Snapshot
// tokens are bound to this subject and its permission generation, not to a client offset.
func WithSubject(r *http.Request, subject string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), subjectKey{}, subject))
}

func getSubject(r *http.Request) (string, error) {
	subject, ok := r.Context().Value(subjectKey{}).(string)
	if !ok || subject == "" {
		return "", errors.ScimError{Detail: "the SCIM request has no authenticated subject", Status: http.StatusForbidden}
	}
	return subject, nil
}

// HeaderSink collects response headers a SCIM handler cannot set directly because the
// elimity library owns the ResponseWriter. The controller flushes them before the first
// byte of the body is written.
type HeaderSink struct {
	mu      sync.Mutex
	headers [][2]string
}

func (s *HeaderSink) Add(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = append(s.headers, [2]string{key, value})
}

func (s *HeaderSink) Headers() [][2]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][2]string, len(s.headers))
	copy(out, s.headers)
	return out
}

// WithHeaderSink attaches the sink the snapshot token is published through.
func WithHeaderSink(r *http.Request, sink *HeaderSink) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), headerSinkKey{}, sink))
}

func getHeaderSink(r *http.Request) *HeaderSink {
	sink, _ := r.Context().Value(headerSinkKey{}).(*HeaderSink)
	return sink
}

func isOrganizationAllowed(r *http.Request, owner string) bool {
	organization, err := getOrganization(r)
	return err == nil && (organization == "" || organization == owner)
}

func checkOrganization(r *http.Request, owner string) error {
	if !isOrganizationAllowed(r, owner) {
		return errors.ScimError{Detail: "the organization: " + owner + " is not allowed", Status: http.StatusForbidden}
	}
	return nil
}
