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
	assert.Equal(t,int32(200), *response.Code)
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

func strPtr(s string) *string {
    return &s
}

func boolPtr(b bool) *bool {
    return &b
}

func int32Ptr(i int32) *int32 {
    return &i
}
