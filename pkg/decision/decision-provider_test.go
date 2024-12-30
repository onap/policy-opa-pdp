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
	"github.com/open-policy-agent/opa/sdk"
	"net/http"
	"net/http/httptest"
	"os"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	opasdk "policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/pdpstate"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
	assert.Contains(t, rec.Body.String(), "Policy used to make decision is nil")
}

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
	assert.Contains(t, rec.Body.String(), " System Is In PASSIVE State")
}

// New
// TestOpaDecision_ValidRequest tests if the request is handled correctly
// Utility function to return a pointer to a string
func ptrString(s string) *string {
	return &s
}

// Utility function to return a pointer to a map
func ptrMap(m map[string]interface{}) *map[string]interface{} {
	return &m
}

// Utility function to return a pointer to a OPADecisionResponseDecision
func ptrOPADecisionResponseDecision(decision oapicodegen.OPADecisionResponseDecision) *oapicodegen.OPADecisionResponseDecision {
	return &decision
}

func TestWriteOpaJSONResponse(t *testing.T) {
	rec := httptest.NewRecorder()

	// Use correct type for Decision, which is a pointer to OPADecisionResponseDecision
	decision := oapicodegen.OPADecisionResponseDecision("PERMIT")
	data := &oapicodegen.OPADecisionResponse{
		Decision:   ptrOPADecisionResponseDecision(decision), // Correct use of pointer
		PolicyName: ptrString("test-policy"),
		Output:     ptrMap(map[string]interface{}{"key": "value"}),
	}

	writeOpaJSONResponse(rec, http.StatusOK, *data)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"decision":"PERMIT"`)
	assert.Contains(t, rec.Body.String(), `"policyName":"test-policy"`)
}

func TestWriteErrorJSONResponse(t *testing.T) {
	rec := httptest.NewRecorder()

	// ErrorResponse struct uses pointers for string fields, so we use ptrString()
	errorResponse := oapicodegen.ErrorResponse{
		ErrorMessage: ptrString("Bad Request"),
	}

	writeErrorJSONResponse(rec, http.StatusBadRequest, "Bad Request", errorResponse)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), `"errorMessage":"Bad Request"`)
}

func TestCreateSuccessDecisionResponse(t *testing.T) {
	// Input values for creating the response
	statusMessage := "Success"
	decision := oapicodegen.OPADecisionResponseDecision("PERMIT")
	policyName := "policy-name"
	output := map[string]interface{}{"key": "value"}

	// Call the createSuccessDecisionResponse function
	response := createSuccessDecisionResponse(statusMessage, string(decision), policyName, output)

	// Assertions

	// Check the StatusMessage field
	assert.Equal(t, *response.StatusMessage, statusMessage, "StatusMessage should match")

	// Check the Decision field (it should be a pointer to the string "PERMIT")
	assert.Equal(t, *response.Decision, decision, "Decision should match")

	// Check the PolicyName field
	assert.Equal(t, *response.PolicyName, policyName, "PolicyName should match")

	// Check the Output field
	assert.Equal(t, *response.Output, output, "Output should match")
}

func TestApplyPolicyFilter(t *testing.T) {
	originalPolicy := map[string]interface{}{
		"policy1": map[string]interface{}{"key1": "value1"},
		"policy2": map[string]interface{}{"key2": "value2"},
	}
	filter := []string{"policy1"}
	result := applyPolicyFilter(originalPolicy, filter)

	assert.NotNil(t, result)
	assert.Len(t, result, 1)
	assert.Contains(t, result, "policy1")
}

func TestWriteOpaJSONResponse_Error(t *testing.T) {
	rec := httptest.NewRecorder()

	// Simulate an error response
	statusMessage := "Error processing request"
	decision := oapicodegen.OPADecisionResponseDecision("DENY")
	policyName := "error-policy"
	output := map[string]interface{}{"errorDetail": "Invalid input"}

	// Create a response object for error scenario
	data := &oapicodegen.OPADecisionResponse{
		Decision:      ptrOPADecisionResponseDecision(decision), // Use correct pointer
		PolicyName:    ptrString(policyName),
		Output:        ptrMap(output),
		StatusMessage: ptrString(statusMessage),
	}

	writeOpaJSONResponse(rec, http.StatusBadRequest, *data)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, rec.Code, "Expected HTTP 400 status code")
	assert.Contains(t, rec.Body.String(), `"decision":"DENY"`, "Response should contain 'DENY' decision")
	assert.Contains(t, rec.Body.String(), `"policyName":"error-policy"`, "Response should contain the policy name")
	assert.Contains(t, rec.Body.String(), `"statusMessage":"Error processing request"`, "Response should contain the status message")
	assert.Contains(t, rec.Body.String(), `"errorDetail":"Invalid input"`, "Response should contain the error detail")
}

func TestWriteOpaJSONResponse_Success(t *testing.T) {
	// Prepare test data
	decisionRes := oapicodegen.OPADecisionResponse{
		StatusMessage: ptrString("Success"),
		Decision:      (*oapicodegen.OPADecisionResponseDecision)(ptrString("PERMIT")),
		PolicyName:    ptrString("TestPolicy"),
		Output:        &map[string]interface{}{"key": "value"},
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
	if *result.StatusMessage != "Success" {
		t.Errorf("Expected StatusMessage 'Success', got '%s'", *result.StatusMessage)
	}
}

func TestWriteOpaJSONResponse_EncodingError(t *testing.T) {
	// Prepare invalid test data to trigger JSON encoding error
	decisionRes := oapicodegen.OPADecisionResponse{
		// Introducing an invalid type to cause encoding failure
		Output: &map[string]interface{}{"key": make(chan int)},
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
		"allowed": true,
	},
}

var mockDecisionResult2 = &sdk.DecisionResult{
	Result: map[string]interface{}{
		"allow": "true",
	},
}

var mockDecisionResultUnexp = &sdk.DecisionResult{
	Result: map[int]interface{}{
		123: 123,
	},
}
var mockDecisionResultBoolFalse = &sdk.DecisionResult{
	Result: false,
}

var mockDecisionResultBool = &sdk.DecisionResult{
	Result: true,
}

var mockDecisionReq = oapicodegen.OPADecisionRequest{
	PolicyName:   ptrString("mockPolicy"),
	PolicyFilter: &[]string{"filter1", "filter2"},
	//Input:        map[string]interface{}{"key": "value"},
}

var mockDecisionReq2 = oapicodegen.OPADecisionRequest{
	PolicyName:   ptrString("mockPolicy"),
	PolicyFilter: &[]string{"allow", "filter2"},
	//Input:        map[string]interface{}{"key": "value"},
}

// Test to check invalid UUID in request
func Test_Invalid_request_UUID(t *testing.T) {
	originalGetInstance := GetOPASingletonInstance
	GetOPASingletonInstance = func() (*sdk.OPA, error) {
		opa, err := sdk.New(context.Background(), sdk.Options{
			ID: "mock-opa-instance",
			// Any necessary options for mocking can go here
		})
		if err != nil {
			return nil, err
		}
		return opa, nil
	}

	defer func() {
		GetOPASingletonInstance = originalGetInstance
	}()
	GetOPASingletonInstance = originalGetInstance
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	body := map[string]interface{}{"PolicyName": "data.policy"}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	req.Header.Set("X-ONAP-RequestID", "valid-uuid")
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

	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()
	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), "PERMIT")
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
	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()

	OpaDecision(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
	assert.Empty(t, res.Body.String())
}

// Test for Policy filter with invalid/not applicable Decision result
func Test_Policy_Filter_with_invalid_decision_result(t *testing.T) {
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
	assert.Contains(t, res.Body.String(), "NOTAPPLICABLE")
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

	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()
	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), "PERMIT")
}

// Test with OPA Decision of boolean type with false
func Test_Successful_decision_allow_false(t *testing.T) {
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

	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()

	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), "OPA Allowed")
}

// Test with OPA Decision of boolean type with false having filter
func Test_decision_result_false_with_Filter(t *testing.T) {
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
			// Simulate an error to trigger the second error block
			return mockDecisionResultBool, nil
		},
	)
	defer patch.Unpatch()
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
	assert.Contains(t, res.Body.String(), "OPA Allowed")
}

// Test with OPA Decision of boolean type with true having filter
func Test_decision_result_true_with_Filter(t *testing.T) {
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
			return mockDecisionResultBoolFalse, nil
		},
	)
	defer patch.Unpatch()
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
	assert.Contains(t, res.Body.String(), "Denied")
}

// Test with OPA Decision with String type
func Test_decision_Result_String(t *testing.T) {
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
					"allowed": "deny",
				},
			}
			return mockDecisionResult, nil
		},
	)
	defer patch.Unpatch()
	body := map[string]interface{}{"PolicyName": jsonString}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", bytes.NewBuffer(jsonBody))
	res := httptest.NewRecorder()

	OpaDecision(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), "DENY")
}

// Test with OPA Decision with String type wth filtered result
func Test_decision_Result_String_with_filtered_Result(t *testing.T) {
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
			// Simulate an error to trigger the second error block
			return mockDecisionResult2, nil
		},
	)
	defer patch.Unpatch()
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
	assert.Contains(t, res.Body.String(), "NOTAPPLICABLE")

}

// Test with OPA Decision with unexpected type wth filtered result
func Test_decision_with_filtered_Result_as_unexpected_Res_Type(t *testing.T) {
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
			// Simulate an error to trigger the second error block
			return mockDecisionResultUnexp, nil
		},
	)
	defer patch.Unpatch()
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
	assert.Contains(t, res.Body.String(), "INDETERMINATE")
}

// Test with OPA Decision with Error in response
func TestWriteErrorJSONResponse_EncodingFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	errorMessage := "Test error message"
	policyName := "TestPolicy"
	responseCode := oapicodegen.ErrorResponseResponseCode("500")
	errorDetails := []string{"Detail 1", "Detail 2"}
	mockDecisionExc := oapicodegen.ErrorResponse{
		ErrorDetails: &errorDetails,
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
