// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024: Deutsche Telekom
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//   SPDX-License-Identifier: Apache-2.0
//   ========================LICENSE_END===================================
//

package api

import (
	"net/http"
	"net/http/httptest"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/pkg/bundleserver"
	"policy-opa-pdp/pkg/decision"
	"policy-opa-pdp/pkg/healthcheck"
	"testing"
)

// Mock configuration
func init() {
	cfg.Username = "testuser"
	cfg.Password = "testpass"
}

func TestRegisterHandlers(t *testing.T) {
	RegisterHandlers()

	tests := []struct {
		path       string
		handler    http.HandlerFunc
		statusCode int
	}{
		{"/policy/pdpx/v1/decision", decision.OpaDecision, http.StatusUnauthorized},
		{"/opa/bundles/", bundleserver.GetBundle, http.StatusInternalServerError},
		{"/ready", readinessProbe, http.StatusOK},
		{"/policy/pdpx/v1/healthcheck", healthcheck.HealthCheckHandler, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		req, err := http.NewRequest("GET", tt.path, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		rr := httptest.NewRecorder()
		http.DefaultServeMux.ServeHTTP(rr, req)

		if status := rr.Code; status != tt.statusCode {
			t.Errorf("handler for %s returned wrong status code: got %v want %v", tt.path, status, tt.statusCode)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	handler := basicAuth(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		username   string
		password   string
		statusCode int
	}{
		{"testuser", "testpass", http.StatusOK},
		{"wronguser", "wrongpass", http.StatusUnauthorized},
		{"", "", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.SetBasicAuth(tt.username, tt.password)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != tt.statusCode {
			t.Errorf("basicAuth returned wrong status code: got %v want %v", status, tt.statusCode)
		}
	}
}

func TestReadinessProbe(t *testing.T) {
	req, err := http.NewRequest("GET", "/ready", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(readinessProbe)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("readinessProbe returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := "Ready"
	if rr.Body.String() != expected {
		t.Errorf("readinessProbe returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}
