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
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/pkg/decision"
	"policy-opa-pdp/pkg/healthcheck"
	"testing"
	"time"
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
		// Readiness probe must return 200 without credentials
		{"/policy/pdpo/v1/readiness", readinessProbe, http.StatusOK},
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

// TestValidateCredentials verifies that constant-time comparison preserves
// the same accept/reject logic as the previous equality check.
func TestValidateCredentials(t *testing.T) {
	tests := []struct {
		username string
		password string
		want     bool
	}{
		{"testuser", "testpass", true},
		{"wronguser", "testpass", false},
		{"testuser", "wrongpass", false},
		{"wronguser", "wrongpass", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got := validateCredentials(tt.username, tt.password)
		if got != tt.want {
			t.Errorf("validateCredentials(%q, %q) = %v, want %v", tt.username, tt.password, got, tt.want)
		}
	}
}

// TestValidateCredentialsEmptyPasswordBypass verifies that an unset (empty)
// configured password is rejected, closing the subtle.ConstantTimeCompare("","")
// bypass where an attacker could authenticate with an empty password.
func TestValidateCredentialsEmptyPasswordBypass(t *testing.T) {
	// Save and restore cfg values so this test does not affect others.
	origUsername := cfg.Username
	origPassword := cfg.Password
	t.Cleanup(func() {
		cfg.Username = origUsername
		cfg.Password = origPassword
	})

	tests := []struct {
		name             string
		configUsername   string
		configPassword   string
		suppliedUsername string
		suppliedPassword string
		want             bool
	}{
		{
			name:             "empty configured password rejects empty supplied password",
			configUsername:   "policyadmin",
			configPassword:   "",
			suppliedUsername: "policyadmin",
			suppliedPassword: "",
			want:             false,
		},
		{
			name:             "empty configured password rejects non-empty supplied password",
			configUsername:   "policyadmin",
			configPassword:   "",
			suppliedUsername: "policyadmin",
			suppliedPassword: "somepassword",
			want:             false,
		},
		{
			name:             "non-empty credentials still match correctly",
			configUsername:   "policyadmin",
			configPassword:   "secret",
			suppliedUsername: "policyadmin",
			suppliedPassword: "secret",
			want:             true,
		},
		{
			name:             "empty supplied password rejected against non-empty configured password",
			configUsername:   "policyadmin",
			configPassword:   "secret",
			suppliedUsername: "policyadmin",
			suppliedPassword: "",
			want:             false,
		},
		{
			name:             "empty configured username rejects any request",
			configUsername:   "",
			configPassword:   "secret",
			suppliedUsername: "",
			suppliedPassword: "secret",
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.Username = tt.configUsername
			cfg.Password = tt.configPassword
			got := validateCredentials(tt.suppliedUsername, tt.suppliedPassword)
			if got != tt.want {
				t.Errorf("validateCredentials(%q, %q) with config(%q, %q) = %v, want %v",
					tt.suppliedUsername, tt.suppliedPassword,
					tt.configUsername, tt.configPassword,
					got, tt.want)
			}
		})
	}
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
