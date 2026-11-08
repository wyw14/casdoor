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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

// Handler is the HTTP entry point of the Casdoor SCIM API. It wraps the upstream SCIM
// server to add the bulk endpoint and to advertise only the bulk capabilities that are
// actually implemented; every other request is delegated unchanged.
var Handler http.Handler = scimHandler{}

type scimHandler struct{}

func (scimHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v2")
	switch {
	case r.Method == http.MethodPost && path == "/Bulk":
		ServeBulkHTTP(w, r)
		return
	case r.Method == http.MethodGet && path == "/ServiceProviderConfig":
		serveServiceProviderConfig(w, r)
		return
	default:
		Server.ServeHTTP(w, r)
	}
}

// serveServiceProviderConfig reuses the upstream configuration and overwrites only the
// bulk section with the limits that ServeBulkHTTP really enforces.
func serveServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	recorder := httptest.NewRecorder()
	Server.ServeHTTP(recorder, r)

	if recorder.Code != http.StatusOK {
		copyRecorderResponse(w, recorder)
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &config); err != nil {
		copyRecorderResponse(w, recorder)
		return
	}
	config["bulk"] = map[string]interface{}{
		"supported":      true,
		"maxOperations":  BulkMaxOperations,
		"maxPayloadSize": BulkMaxPayloadSize,
	}

	raw, err := json.Marshal(config)
	if err != nil {
		copyRecorderResponse(w, recorder)
		return
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func copyRecorderResponse(w http.ResponseWriter, recorder *httptest.ResponseRecorder) {
	for key, values := range recorder.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(recorder.Code)
	_, _ = w.Write(recorder.Body.Bytes())
}
