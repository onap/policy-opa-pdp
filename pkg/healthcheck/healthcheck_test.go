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

// Package healthcheck provides functionalities for handling health check requests.
// This package includes a function to handle HTTP requests for health checks
// and respond with the health status of the service.
package healthcheck

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/pdpattributes"
	"testing"
)

// Success Test Case for HealthCheckHandler
func TestHealthCheckHandler_Success(t *testing.T) {
	// Prepare a request to the health check endpoint
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	w := httptest.NewRecorder()

	// Call the HealthCheckHandler with the test request and response recorder
	HealthCheckHandler(w, req)

	// Check if the status code is OK (200)
	assert.Equal(t, http.StatusOK, w.Code)

	// Check if the response is a valid JSON and contains the expected fields
	var response oapicodegen.HealthCheckReport
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, pdpattributes.PdpName, *response.Name)
	assert.Equal(t, "self", *response.Url)
	assert.True(t, *response.Healthy)
	assert.Equal(t, int32(200), *response.Code)
	assert.Equal(t, "alive", *response.Message)
}

// Failure Test Case for HealthCheckHandler (Simulate failure by forcing an error)
func TestHealthCheckHandler_Failure(t *testing.T) {
	// Simulate an error by modifying the handler or the response
	// For the sake of testing, we'll modify the handler to return a failure message
	// You could also simulate a failure by forcing an error within the handler code itself
	HealthCheckFailureHandler := func(w http.ResponseWriter, r *http.Request) {
		// Modify response to simulate failure
		response := oapicodegen.HealthCheckReport{
			Name:    strPtr("Unknown"),
			Url:     strPtr("self"),
			Healthy: boolPtr(false),
			Code:    int32Ptr(500),
			Message: strPtr("error"),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
	}

	// Prepare a request to the health check endpoint
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	w := httptest.NewRecorder()

	// Call the HealthCheckHandler with the test request and response recorder
	HealthCheckFailureHandler(w, req)

	// Check if the status code is InternalServerError (500)
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check if the response is a valid JSON and contains the expected failure fields
	var response oapicodegen.HealthCheckReport
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.False(t, *response.Healthy)
	assert.Equal(t, int32(500), *response.Code)
	assert.Equal(t, "error", *response.Message)

}

func TestHealthCheckHandler_ValidUUID(t *testing.T) {
	// Prepare a request with a valid UUID in the header
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	validUUID := "123e4567-e89b-12d3-a456-426614174000"
	req.Header.Set("X-ONAP-RequestID", validUUID)
	w := httptest.NewRecorder()

	// Call the HealthCheckHandler
	HealthCheckHandler(w, req)

	// Check if the status code is OK (200)
	assert.Equal(t, http.StatusOK, w.Code)

	// Check the response headers
	assert.Equal(t, validUUID, w.Header().Get("X-ONAP-RequestID"))

	// Check the response body
	var response oapicodegen.HealthCheckReport
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, pdpattributes.PdpName, *response.Name)
	assert.Equal(t, "self", *response.Url)
	assert.True(t, *response.Healthy)
	assert.Equal(t, int32(200), *response.Code)
	assert.Equal(t, "alive", *response.Message)
}

func TestHealthCheckHandler_InvalidUUID(t *testing.T) {
	// Prepare a request with an invalid UUID in the header
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	req.Header.Set("X-ONAP-RequestID", "invalid-uuid")
	w := httptest.NewRecorder()

	// Call the HealthCheckHandler
	HealthCheckHandler(w, req)

	// Check if the status code is OK (200)
	assert.Equal(t, http.StatusOK, w.Code)

	// Check the fallback request ID
	assert.Equal(t, "000000000000", w.Header().Get("X-ONAP-RequestID"))
}

func TestHealthCheckHandler_MissingUUID(t *testing.T) {
	// Prepare a request with no UUID header
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	w := httptest.NewRecorder()

	// Call the HealthCheckHandler
	HealthCheckHandler(w, req)

	// Check if the status code is OK (200)
	assert.Equal(t, http.StatusOK, w.Code)

	// Check the fallback request ID
	assert.Equal(t, "000000000000", w.Header().Get("X-ONAP-RequestID"))
}

func TestHealthCheckHandler_EmptyResponseBody(t *testing.T) {
	// Simulate a case where the handler fails to set the response body
	EmptyResponseHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// Prepare a request to the health check endpoint
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	w := httptest.NewRecorder()

	// Call the modified handler
	EmptyResponseHandler(w, req)

	// Check if the status code is OK (200)
	assert.Equal(t, http.StatusOK, w.Code)

	// Try decoding the empty body
	var response oapicodegen.HealthCheckReport
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.Error(t, err)
}

func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

func int32Ptr(i int32) *int32 {
	return &i
}
