// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"net/http"
	"strings"
	"sync"

	"github.com/casdoor/casdoor/scim"
)

// snapshotHeaderWriter flushes the snapshot token collected by the SCIM handler into
// the real response headers before the library writes the first body byte.
type snapshotHeaderWriter struct {
	http.ResponseWriter
	sink *scim.HeaderSink
	once sync.Once
}

func (w *snapshotHeaderWriter) flush() {
	w.once.Do(func() {
		for _, header := range w.sink.Headers() {
			w.Header().Set(header[0], header[1])
		}
	})
}

func (w *snapshotHeaderWriter) WriteHeader(statusCode int) {
	w.flush()
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *snapshotHeaderWriter) Write(data []byte) (int, error) {
	w.flush()
	return w.ResponseWriter.Write(data)
}

func (c *RootController) HandleScim() {
	organization, ok := c.RequireAdmin()
	if !ok {
		return
	}
	subject, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	request := scim.WithOrganization(c.Ctx.Request, organization)
	request = scim.WithSubject(request, subject.GetId())

	if scim.HandleSnapshotRelease(c.Ctx.ResponseWriter, request) {
		return
	}

	sink := &scim.HeaderSink{}
	request = scim.WithHeaderSink(request, sink)

	path := c.Ctx.Request.URL.Path
	request.URL.Path = strings.TrimPrefix(path, "/scim")
	scim.Server.ServeHTTP(&snapshotHeaderWriter{ResponseWriter: c.Ctx.ResponseWriter, sink: sink}, request)
}
