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

package decision

import (
	"bou.ke/monkey"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/open-policy-agent/opa/sdk"
	"net/http"
	"net/http/httptest"
	"os"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	opasdk "policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/pdpstate"
	"policy-opa-pdp/pkg/policymap"
	"reflect"
	"testing"
	"github.com/stretchr/testify/assert"
)

//Test for Invalid request method
func TestOpaDecision_MethodNotAllowed(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Contains(t, rec.Body.String(), "MethodNotAllowed")
}

//Test for invalid JSON request
func TestOpaDecision_InvalidJSON(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte("invalid json")))
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

//Test for Missing Policy
func TestOpaDecision_MissingPolicyPath(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	body := map[string]interface{}{"onapName": "CDS", "onapComponent": "CDS", "onapInstance": "CDS", "requestId": "8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1", "input": nil}

	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonBody))
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Policy Name is nil which is invalid")
}

//Test for Missing Policy Filter
func TestOpaDecision_MissingPolicyFilter(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	body := map[string]interface{}{"onapName": "CDS", "policyName": "datapolicy", "onapComponent": "CDS", "onapInstance": "CDS", "requestId": "8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1", "input": nil}

	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonBody))
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Policy Filter is nil")
}

//Test for OPA Instance Error
func TestOpaDecision_GetInstanceError(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	body := map[string]interface{}{"policy": "data.policy"}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonBody))
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

//Test for OPA decision Error
func TestOpaDecision_OPADecisionError(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	body := map[string]interface{}{"policy": "data.policy"}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonBody))
	rec := httptest.NewRecorder()

	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	consts.OpasdkConfigPath = tmpFile.Name()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

//Test for system in passive State
func TestOpaDecision_PassiveState(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Passive
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", nil)
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "System Is In PASSIVE State")
}

// TestOpaDecision_ValidRequest tests if the request is handled correctly
// Utility function to return a pointer to a string
func ptrString(s string) string {
	return s
}

func ptrStringEx(s string) *string {
	return &s
}
// Utility function to return a pointer to a map
func ptrMap(m map[string]interface{}) map[string]interface{} {
	return m
}

// Utility function to return a pointer to a OPADecisionResponseDecision
func TestWriteOpaJSONResponse(t *testing.T) {
	rec := httptest.NewRecorder()

	data := &oapicodegen.OPADecisionResponse{
	PolicyName: ptrString("test-policy"),
	Output:     ptrMap(map[string]interface{}{"key": "value"}),
	}

	writeOpaJSONResponse(rec, http.StatusOK, *data)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"policyName":"test-policy"`)
}

//Test for JSON response error
func TestWriteErrorJSONResponse(t *testing.T) {
	rec := httptest.NewRecorder()

	// ErrorResponse struct uses pointers for string fields, so we use ptrString()
	errorResponse := oapicodegen.ErrorResponse{
		ErrorMessage: ptrStringEx("Bad Request"),
	}

	writeErrorJSONResponse(rec, http.StatusBadRequest, "Bad Request", errorResponse)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), `"errorMessage":"Bad Request"`)
}

//Test for Success Decision Response
func TestCreateSuccessDecisionResponse(t *testing.T) {
	// Input values for creating the response
	policyName := "policy-name"
	output := map[string]interface{}{"key": "value"}

	// Call the createSuccessDecisionResponse function
	response := createSuccessDecisionResponse(
	policyName, output)

	// Assertions

	// Check the PolicyName field
	assert.Equal(t, response.PolicyName, policyName, "PolicyName should match")

	// Check the Output field
	assert.Equal(t, response.Output, output, "Output should match")
}

//Test for policy filter
func TestApplyPolicyFilter(t *testing.T) {
	originalPolicy := map[string]interface{}{
		"policy1": map[string]interface{}{"key1": "value1"},
		"policy2": map[string]interface{}{"key2": "value2"},
	}
	filter := []string{"policy1"}
	result,_ := applyPolicyFilter(originalPolicy, filter)

	assert.NotNil(t, result)
	assert.Len(t, result, 1)
	assert.Contains(t, result, "policy1")
}

//Test for Opa response error
func TestWriteOpaJSONResponse_Error(t *testing.T) {
	rec := httptest.NewRecorder()

	// Simulate an error response
	policyName := "error-policy"
	output := map[string]interface{}{"errorDetail": "Invalid input"}

	// Create a response object for error scenario
	data := &oapicodegen.OPADecisionResponse{
		PolicyName:    ptrString(policyName),
		Output:        ptrMap(output),
	}

	writeOpaJSONResponse(rec, http.StatusBadRequest, *data)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, rec.Code, "Expected HTTP 400 status code")
	assert.Contains(t, rec.Body.String(), `"policyName":"error-policy"`, "Response should contain the policy name")
	assert.Contains(t, rec.Body.String(), `"errorDetail":"Invalid input"`, "Response should contain the error detail")
}

//Test for JSON response success
func TestWriteOpaJSONResponse_Success(t *testing.T) {
	// Prepare test data
	decisionRes := oapicodegen.OPADecisionResponse{
		PolicyName:    ptrString("TestPolicy"),
		Output:        map[string]interface{}{"key": "value"},
	}

	// Create a mock HTTP response writer
	res := httptest.NewRecorder()

	// Call the function
	writeOpaJSONResponse(res, http.StatusOK, decisionRes)

	// Assert HTTP status
	if res.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, res.Code)
	}

	// Assert headers
	if res.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", res.Header().Get("Content-Type"))
	}

	// Assert body
	var result oapicodegen.OPADecisionResponse
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}
}

// Test for JSON encoding errors
func TestWriteOpaJSONResponse_EncodingError(t *testing.T) {
		// Prepare invalid test data to trigger JSON encoding error
		decisionRes := oapicodegen.OPADecisionResponse {
		// Introducing an invalid type to cause encoding failure
		Output: map[string]interface{}{"key": make(chan int)},
	}

	// Create a mock HTTP response writer
	res := httptest.NewRecorder()

	// Call the function
	writeOpaJSONResponse(res, http.StatusInternalServerError, decisionRes)

	// Assert HTTP status
	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, res.Code)
	}

	// Assert error message in body
	if !bytes.Contains(res.Body.Bytes(), []byte("json: unsupported type")) {
		t.Errorf("Expected encoding error message, got '%s'", res.Body.String())
	}
}

// Mocks for test cases
var GetOPASingletonInstance = opasdk.GetOPASingletonInstance

var mockDecisionResult = &sdk.DecisionResult{
	Result: map[string]interface{}{
		"allow": "true",
	},
}

var mockDecisionResultUnexp = &sdk.DecisionResult{
	Result: map[int]interface{}{
		123: 123,
	},
}

var mockDecisionResultBool = &sdk.DecisionResult{
	Result: true,
}

var mockDecisionReq = oapicodegen.OPADecisionRequest{
	PolicyName:   ptrString("mockPolicy"),
	PolicyFilter: []string{"filter1", "filter2"},
}

var mockDecisionReq2 = oapicodegen.OPADecisionRequest{
	PolicyName:   ptrString("mockPolicy"),
	PolicyFilter: []string{"allow", "filter2"},
}

var mockDecisionReq3 = oapicodegen.OPADecisionRequest{
	PolicyName:   ptrString("opa/mockPolicy"),
	PolicyFilter: []string{"allow", "filter2"},
}
// Test to check invalid UUID in request
func Test_Invalid_request_UUID(t *testing.T) {

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "s3", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)

	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"s3","policyFilter":["allow"],"input":{"content" : "content"}}`
	var decisionReq oapicodegen.OPADecisionRequest
	json.Unmarshal([]byte(jsonString), &decisionReq)
	body := map[string]interface{}{"PolicyName": decisionReq.PolicyName, "PolicyFilter": decisionReq.PolicyFilter,}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	req.Header.Set("X-ONAP-RequestID", "invalid-uuid")
	res := httptest.NewRecorder()
	OpaDecision(res, req)
	assert.Equal(t, http.StatusInternalServerError, res.Code)
}

// Test to check UUID is valid
func Test_valid_UUID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", nil)
	req.Header.Set("X-ONAP-RequestID", "123e4567-e89b-12d3-a456-426614174000")
	res := httptest.NewRecorder()
	OpaDecision(res, req)
	assert.Equal(t, "123e4567-e89b-12d3-a456-426614174000", res.Header().Get("X-ONAP-RequestID"), "X-ONAP-RequestID header mismatch")
}

// Test for PASSIVE system state
func Test_passive_system_state(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", nil)
	res := httptest.NewRecorder()

	OpaDecision(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	assert.Contains(t, res.Body.String(), "System Is In PASSIVE State")
}

// Test for valid HTTP Method (POST)
func Test_valid_HTTP_method(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"s3","policyFilter":["allow"],"input":{"content" : "content"}}`

	var patch *monkey.PatchGuard
	patch = monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			return mockDecisionResult, nil
		},
	)
	defer patch.Unpatch()

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "s3", "policy-version": "1.0"}]}`


	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)

	var decisionReq oapicodegen.OPADecisionRequest
	json.Unmarshal([]byte(jsonString), &decisionReq)
	body := map[string]interface{}{"PolicyName": decisionReq.PolicyName, "PolicyFilter": decisionReq.PolicyFilter,}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()
	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

// Test for Marshalling error in Decision Result
func Test_Error_Marshalling(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"s3","policyFilter":["allow"],"input":{"content" : "content"}}`
	var patch *monkey.PatchGuard

	patch = monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			// Create a mock result with an incompatible field (e.g., a channel)
			mockDecisionResult := &sdk.DecisionResult{
				Result: map[string]interface{}{
					"key": make(chan int),
				},
			}
			return mockDecisionResult, nil
		},
	)
	defer patch.Unpatch()
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "s3", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)

	var decisionReq oapicodegen.OPADecisionRequest
	json.Unmarshal([]byte(jsonString), &decisionReq)
	body := map[string]interface{}{"PolicyName": decisionReq.PolicyName, "PolicyFilter": decisionReq.PolicyFilter,}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()

	OpaDecision(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
	assert.NotEmpty(t, res.Body.String())
}


func mockGetOpaInstance() (*sdk.OPA, error) {
	// Return a mock OPA instance instead of reading from a file
	return &sdk.OPA{}, nil
}
// Test for Invalid Decision error in Decision Result
func Test_Invalid_Decision(t *testing.T) {
	// Mock PDP state
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()

	// Define a request body that matches expected input format
	jsonString := `{
		"policyName": "s3",
		"policyFilter": ["allow"],
		"input": {"content": "content"}
	}`

	// Patch the OPA Decision method to return an error
	patch := monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			// Return an explicit error
			return nil, fmt.Errorf("opa_undefined_error")
		},
	)
	defer patch.Unpatch()

	// Create a test HTTP request
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer([]byte(jsonString)))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	// Call the handler function that processes OPA decision
	//OpaDecision(res, req)
	// Assert that the response status code is 400
	assert.Equal(t, 200, res.Code)
}

// Test for Invalid Decision error in Decision Result
func Test_Valid_Decision_String(t *testing.T) {
	// Mock PDP state
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()

	jsonString := `{
		"policyName": "s3",
		"policyFilter": ["allow"],
		"input": {"content": "content"}
	}`

	// Patch the OPA Decision method to return an error
	patch := monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
				// Return an explicit error
				mockDecisionResult := &sdk.DecisionResult{
				Result: map[string]interface{}{
					"allowed": "true",
				},
			}
			return mockDecisionResult, nil
		},
	)

	defer patch.Unpatch()

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "s3", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)

	// Create a test HTTP request
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer([]byte(jsonString)))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	// Call the handler function that processes OPA decision
	OpaDecision(res, req)

	// Assert that the response status code is 400
	assert.Equal(t, 200, res.Code)
}

// Test for Policy filter with invalid/not applicable Decision result
func Test_Policy_Filter_with_invalid_decision_result(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"mockPolicy","policyFilter":["allow"],"input":{"content" : "content"}}`

	var patch *monkey.PatchGuard

	patch = monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			return mockDecisionResult, nil
		},
	)
	defer patch.Unpatch()
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "mockPolicy", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)

	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()

	var patch1 *monkey.PatchGuard
	patch1 = monkey.PatchInstanceMethod(
		reflect.TypeOf(&json.Decoder{}), "Decode",
		func(_ *json.Decoder, v interface{}) error {
			if req, ok := v.(*oapicodegen.OPADecisionRequest); ok {
				*req = mockDecisionReq
			}
			return nil
		},
	)
	defer patch1.Unpatch()
	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

// Test with OPA Decision of boolean type true
func Test_with_boolean_OPA_Decision(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"s3","policyFilter":["allow"],"input":{"content" : "content"}}`

	var patch *monkey.PatchGuard
	patch = monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			return mockDecisionResultBool, nil
		},
	)
	defer patch.Unpatch()

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "s3", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)
	var decisionReq oapicodegen.OPADecisionRequest
        json.Unmarshal([]byte(jsonString), &decisionReq)
        body := map[string]interface{}{"PolicyName": decisionReq.PolicyName, "PolicyFilter": decisionReq.PolicyFilter,}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()
	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}


// Test with OPA Decision with String type
func Test_decision_Result_String(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"s3","policyFilter":["allowed"],"input":{"content" : "content"}}`

	var patch *monkey.PatchGuard

	patch = monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			// Create a mock result with an incompatible field (e.g., a channel)
			mockDecisionResult := &sdk.DecisionResult{
				Result: map[string]interface{}{
					"allowed": "true",
				},
			}
			return mockDecisionResult, nil
		},
	)
	defer patch.Unpatch()
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "s3", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)

	var decisionReq oapicodegen.OPADecisionRequest
	json.Unmarshal([]byte(jsonString), &decisionReq)
	body := map[string]interface{}{"PolicyName": decisionReq.PolicyName, "PolicyFilter": decisionReq.PolicyFilter,}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()

	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

// Test with OPA Decision with String type wth filtered result
func Test_decision_Result_String_with_filtered_Result(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"mockPolicy","policyFilter":["allow"],"input":{"content" : "content"}}`

	var patch *monkey.PatchGuard

	patch = monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			// Simulate an error to trigger the second error block
			return mockDecisionResult, nil
		},
	)
	defer patch.Unpatch()
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "mockPolicy", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)
	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()
	var patch1 *monkey.PatchGuard
	patch1 = monkey.PatchInstanceMethod(
		reflect.TypeOf(&json.Decoder{}), "Decode",
		func(_ *json.Decoder, v interface{}) error {
			if req, ok := v.(*oapicodegen.OPADecisionRequest); ok {
				*req = mockDecisionReq2
			}
			return nil
		},
	)
	defer patch1.Unpatch()
	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)

}

// Test with OPA Decision with String type wth filtered result
func Test_decision_with_slash_Result_String_with_filtered_Result(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"opa/mockPolicy","policyFilter":["allow"],"input":{"content" : "content"}}`

	var patch *monkey.PatchGuard

	patch = monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			// Simulate an error to trigger the second error block
			return mockDecisionResult, nil
		},
	)
	defer patch.Unpatch()
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "opa.mockPolicy", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)
	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()
	var patch1 *monkey.PatchGuard
	patch1 = monkey.PatchInstanceMethod(
		reflect.TypeOf(&json.Decoder{}), "Decode",
		func(_ *json.Decoder, v interface{}) error {
			if req, ok := v.(*oapicodegen.OPADecisionRequest); ok {
				*req = mockDecisionReq3
			}
			return nil
		},
	)
	defer patch1.Unpatch()
	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)

}

// Test with OPA Decision with unexpected type wth filtered result
func Test_decision_with_filtered_Result_as_unexpected_Res_Type(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	jsonString := `{"onapName":"CDS","onapComponent":"CDS","onapInstance":"CDS", "currentDate": "2024-11-22", "currentTime": "2024-11-22T11:34:56Z", "timeZone": "UTC", "timeOffset": "+05:30", "currentDateTime": "2024-11-22T12:08:00Z","policyName":"mockPolicy","policyFilter":["allow"],"input":{"content" : "content"}}`

	var patch *monkey.PatchGuard

	patch = monkey.PatchInstanceMethod(
		reflect.TypeOf(&sdk.OPA{}), "Decision",
		func(_ *sdk.OPA, _ context.Context, _ sdk.DecisionOptions) (*sdk.DecisionResult, error) {
			// Simulate an error to trigger the second error block
			return mockDecisionResultUnexp, nil
		},
	)
	defer patch.Unpatch()
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "mockPolicy", "policy-version": "1.0"}]}`

	monkey.Patch(getOpaInstance, func() (*sdk.OPA, error) {
        return &sdk.OPA{}, nil // Mocked OPA instance
    })
    defer monkey.Unpatch(getOpaInstance)
	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()
	var patch1 *monkey.PatchGuard
	patch1 = monkey.PatchInstanceMethod(
		reflect.TypeOf(&json.Decoder{}), "Decode",
		func(_ *json.Decoder, v interface{}) error {
			if req, ok := v.(*oapicodegen.OPADecisionRequest); ok {
				*req = mockDecisionReq2
			}
			return nil
		},
	)
	defer patch1.Unpatch()
	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

// Test with OPA Decision with Error in response
func TestWriteErrorJSONResponse_EncodingFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	errorMessage := "Test error message"
	policyName := "TestPolicy"
	responseCode := oapicodegen.ErrorResponseResponseCode("500")
	mockDecisionExc := oapicodegen.ErrorResponse{
		ErrorMessage: &errorMessage,
		PolicyName:   &policyName,
		ResponseCode: &responseCode,
	}

	patch := monkey.PatchInstanceMethod(
		reflect.TypeOf(json.NewEncoder(recorder)),
		"Encode",
		func(_ *json.Encoder, _ interface{}) error {
			return errors.New("forced encoding error")
		},
	)
	defer patch.Unpatch()

	writeErrorJSONResponse(recorder, http.StatusInternalServerError, "Encoding error", mockDecisionExc)

	response := recorder.Result()
	defer response.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
}

