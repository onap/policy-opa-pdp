// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024-2025: Deutsche Telekom
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
	"policy-opa-pdp/pkg/decision"
	"policy-opa-pdp/pkg/healthcheck"
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
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
		{"/policy/pdpo/v1/decision", decision.OpaDecision, http.StatusUnauthorized},
		{"/policy/pdpo/v1/healthcheck", healthcheck.HealthCheckHandler, http.StatusUnauthorized},
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


type mockObserver struct {
	observedDuration float64
}

func (m *mockObserver) Observe(duration float64) {
	m.observedDuration = duration
}

// Test trackDecisionResponseTime function
func TestTrackDecisionResponseTime(t *testing.T) {
	observer := &mockObserver{}
	handler := trackDecisionResponseTime(func(res http.ResponseWriter, req *http.Request) {
		time.Sleep(50 * time.Millisecond)
		res.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/decision", nil)
	res := httptest.NewRecorder()

	handler(res, req)

	assert.NotNil(t, observer.observedDuration)
}

// Test trackDataResponseTime function
func TestTrackDataResponseTime(t *testing.T) {
	observer := &mockObserver{}
	handler := trackDataResponseTime(func(res http.ResponseWriter, req *http.Request) {
		time.Sleep(30 * time.Millisecond)
		res.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/data", nil)
	res := httptest.NewRecorder()

	handler(res, req)

	assert.NotNil(t, observer.observedDuration)
}

// Test trackResponseTime function
func TestTrackResponseTime(t *testing.T) {
	observer := &mockObserver{}

	handler := trackResponseTime(observer, func(res http.ResponseWriter, req *http.Request) {
		time.Sleep(20 * time.Millisecond)
		res.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/response", nil)
	res := httptest.NewRecorder()
	handler(res, req)
	assert.NotNil(t, observer.observedDuration)
}


func TestMetricsHandler(t *testing.T) {
req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
rr := httptest.NewRecorder()

metricsHandler(rr, req)

resp := rr.Result()
defer resp.Body.Close()

assert.Equal(t, http.StatusOK, resp.StatusCode, "expected status OK")

contentType := resp.Header.Get("Content-Type")
assert.Contains(t, contentType, "text/plain", "expected Prometheus content type")

}

func TestReadinessProbe(t *testing.T) {
req := httptest.NewRequest(http.MethodGet, "/ready", nil)
rr := httptest.NewRecorder()

readinessProbe(rr, req)

resp := rr.Result()
defer resp.Body.Close()

assert.Equal(t, http.StatusOK, resp.StatusCode, "expected HTTP 200 OK")

body := rr.Body.String()
assert.Equal(t, "Ready", body, "expected response body to be 'Ready'")
}
