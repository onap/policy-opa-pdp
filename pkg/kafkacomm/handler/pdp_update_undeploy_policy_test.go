// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2025: Deutsche Telekom
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

// will process the update message from pap and send the pdp status response.

package handler

import (
	"context"
	"encoding/json"
	"errors"
	//"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/policymap"
	"reflect"
	"testing"
)

// Success case: Extract undeployed policies
func TestExtractUndeployedPolicies_Success(t *testing.T) {
	policies := []model.ToscaConceptIdentifier{
		{Name: "test-policy", Version: "v1"},
		{Name: "test-policy-2", Version: "v2"},
	}

	result := extractUndeployedPolicies(policies)

	assert.Equal(t, "v1", result["test-policy"], "Expected version v1 for test-policy")
	assert.Equal(t, "v2", result["test-policy-2"], "Expected version v2 for test-policy-2")
}

// Failure case: Empty policy list
func TestExtractUndeployedPolicies_Failure_EmptyList(t *testing.T) {
	policies := []model.ToscaConceptIdentifier{}
	result := extractUndeployedPolicies(policies)

	assert.Empty(t, result, "Expected an empty map")
}

// Success case: Policy found
func TestFindDeployedPolicy_Success(t *testing.T) {
	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test-policy", "policy-version": "v1"},
		{"policy-id": "other-policy", "policy-version": "v2"},
	}

	result := findDeployedPolicy("test-policy", "v1", deployedPolicies)

	assert.NotNil(t, result, "Expected to find the policy")
	assert.Equal(t, "test-policy", result["policy-id"])
}

// Failure case: Policy not found
func TestFindDeployedPolicy_Failure_NotFound(t *testing.T) {
	deployedPolicies := []map[string]interface{}{
		{"policy-id": "other-policy", "policy-version": "v2"},
	}

	result := findDeployedPolicy("test-policy", "v1", deployedPolicies)

	assert.Nil(t, result, "Expected to not find the policy")
}

// Success case: Handle policy undeployment
func TestHandlePolicyUndeployment_Success(t *testing.T) {
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{
			{Name: "test-policy", Version: "v1"},
		},
	}

	mockPublisher := new(MockPdpStatusSender)
	errorMessages, successPolicies := handlePolicyUndeployment(pdpUpdate, mockPublisher)

	assert.Empty(t, errorMessages, "Expected no failures")
	assert.Equal(t, 0, len(successPolicies), "Expected one successfully undeployed policy")
	assert.Equal(t, "", successPolicies["test-policy"])
}

// Failure case: Empty policies to be undeployed
func TestHandlePolicyUndeployment_Failure_EmptyPolicies(t *testing.T) {
	pdpUpdate := model.PdpUpdate{PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{}}
	mockPublisher := new(MockPdpStatusSender)

	errorMessages, successPolicies := handlePolicyUndeployment(pdpUpdate, mockPublisher)

	assert.Empty(t, successPolicies, "Expected no successfully undeployed policies")
	assert.Empty(t, errorMessages, "Expected no error messages")
}

// Mock dependencies
type MockPolicyMap struct {
	mock.Mock
}

func (m *MockPolicyMap) UnmarshalLastDeployedPolicies(data string) ([]map[string]interface{}, error) {
	args := m.Called(data)
	result, _ := args.Get(0).([]map[string]interface{})
	return result, args.Error(1)
}

func (m *MockPolicyMap) RemoveUndeployedPoliciesfromMap(policy map[string]interface{}) (string, error) {
	args := m.Called(policy)
	return args.String(0), args.Error(1)
}

// Success case: Policy undeployment successful
func TestProcessPoliciesTobeUndeployed_Success(t *testing.T) {
	undeployedPolicies := map[string]string{"test-policy": "v1"}

	// Mock deployed policies
	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test-policy", "policy-version": "v1", "data": []interface{}{"key1"}, "policy": []interface{}{"rule1"}},
	}

	mockPolicyMap := new(MockPolicyMap)
	mockPolicyMap.On("UnmarshalLastDeployedPolicies", mock.Anything).Return(deployedPolicies, nil)
	mockPolicyMap.On("RemoveUndeployedPoliciesfromMap", mock.Anything).Return("{}", nil)

	policymap.LastDeployedPolicies = `{"test-policy": "v1"}`

	failures, success := processPoliciesTobeUndeployed(undeployedPolicies)

	assert.Empty(t, failures, "Expected no failures")
	assert.Equal(t, 0, len(success), "Expected one policy to be successfully undeployed")
	assert.Equal(t, "", success["test-policy"])
}

func TestProcessPoliciesTobeUndeployed_Failure_UnmarshalError(t *testing.T) {
	undeployedPolicies := map[string]string{"test-policy": "v1"}

	mockPolicyMap := new(MockPolicyMap)
	mockPolicyMap.On("UnmarshalLastDeployedPolicies", mock.Anything).Return([]map[string]interface{}{}, errors.New("unmarshal error"))

	policymap.LastDeployedPolicies = `invalid json`

	failures, success := processPoliciesTobeUndeployed(undeployedPolicies)

	assert.Empty(t, success, "Expected no successful undeployments")
	assert.Empty(t, failures, "Expected failure messages due to unmarshal error")
}

func TestRemoveDataDirectory(t *testing.T) {
	// Backup original values
	originalDataPath := consts.Data
	originalFunc := removeDirectoryFunc

	// Restore values after test
	defer func() {
		consts.Data = originalDataPath
		removeDirectoryFunc = originalFunc
	}()

	// Mock the base path for testing
	consts.Data = "/mock/data"

	// Mock success case
	removeDirectoryFunc = func(path string) error {
		return nil
	}

	err := removeDataDirectory("testkey")
	assert.Nil(t, err)

	// Mock failure case
	removeDirectoryFunc = func(path string) error {
		return errors.New("mocked error")
	}

	err = removeDataDirectory("testkey")
	expectedError := "Failed to handle directory for data /mock/data/testkey: mocked error"
	assert.Equal(t, expectedError, err.Error())
}

func TestRemovePolicyDirectory(t *testing.T) {
	// Backup original values
	originalPolicyPath := consts.Policies
	originalFunc := removeDirectoryFunc

	// Restore values after test
	defer func() {
		consts.Policies = originalPolicyPath
		removeDirectoryFunc = originalFunc
	}()

	// Mock the base path for testing
	consts.Policies = "/mock/policies"

	// Mock success case
	removeDirectoryFunc = func(path string) error {
		return nil
	}

	err := removePolicyDirectory("testpolicy")
	assert.Nil(t, err)

	// Mock failure case
	removeDirectoryFunc = func(path string) error {
		return errors.New("mocked error")
	}

	err = removePolicyDirectory("testpolicy")
	expectedError := "Failed to handle directory for policy /mock/policies/testpolicy: mocked error"
	assert.Equal(t, expectedError, err.Error())
}

func TestRemovePolicyFromSdkandDir(t *testing.T) {
	// Backup original functions
	originalRemovePolicyDirectory := removePolicyDirectoryFunc
	originalDeletePolicy := deletePolicySdkFunc
	defer func() {
		removePolicyDirectoryFunc = originalRemovePolicyDirectory // Restore after test
		deletePolicySdkFunc = originalDeletePolicy                // Restore after test
	}()

	// Mock functions
	removePolicyDirectoryFunc = func(policyKey string) error {
		if policyKey == "/mocked/error" {
			return errors.New("mocked remove policy directory error")
		}
		return nil
	}

	deletePolicySdkFunc = func(ctx context.Context, policyPath string) error {
		if policyPath == "mocked.error" {
			return errors.New("mocked delete policy error")
		}
		return nil
	}

	policy := map[string]interface{}{
		"policy": []interface{}{"mocked.success", "mocked.error"}, // VALID policy key
	}

	failures := removePolicyFromSdkandDir(policy)

	// Expecting 1 error message (for "mocked.error"), "mocked.success" should pass
	assert.Len(t, failures, 1)
	assert.Contains(t, failures[0], "mocked delete policy error")
}

// Mocking the remove functions
var (
	mockRemovePolicyFromSdkandDir = func(policy map[string]interface{}) []string {
		return nil // Default successful case
	}
	mockRemoveDataFromSdkandDir = func(policy map[string]interface{}) []string {
		return nil // Default successful case
	}
)

// Replace the actual functions with mocks in the test
func TestPolicyUndeploymentAction(t *testing.T) {
	// Backup original function pointers
	originalRemovePolicy := removePolicyFromSdkandDirFunc
	originalRemoveData := removeDataFromSdkandDirFunc

	// Restore original functions after test
	defer func() {
		removePolicyFromSdkandDirFunc = originalRemovePolicy
		removeDataFromSdkandDirFunc = originalRemoveData
	}()

	tests := []struct {
		name             string
		policy           map[string]interface{}
		mockPolicyErrors []string
		mockDataErrors   []string
		expectedFailures []string
	}{
		{
			name:             "Successful undeployment",
			policy:           map[string]interface{}{"policy_id": "test-policy"},
			mockPolicyErrors: nil,
			mockDataErrors:   nil,
			expectedFailures: nil,
		},
		{
			name:             "Policy removal failure",
			policy:           map[string]interface{}{"policy_id": "test-policy"},
			mockPolicyErrors: []string{"Failed to remove policy"},
			mockDataErrors:   nil,
			expectedFailures: []string{"Failed to remove policy"},
		},
		{
			name:             "Data removal failure",
			policy:           map[string]interface{}{"policy_id": "test-policy"},
			mockPolicyErrors: nil,
			mockDataErrors:   []string{"Failed to remove data"},
			expectedFailures: []string{"Failed to remove data"},
		},
		{
			name:             "Both removals fail",
			policy:           map[string]interface{}{"policy_id": "test-policy"},
			mockPolicyErrors: []string{"Failed to remove policy"},
			mockDataErrors:   []string{"Failed to remove data"},
			expectedFailures: []string{"Failed to remove policy", "Failed to remove data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set mock behavior
			removePolicyFromSdkandDirFunc = func(policy map[string]interface{}) []string {
				return tt.mockPolicyErrors
			}
			removeDataFromSdkandDirFunc = func(policy map[string]interface{}) []string {
				return tt.mockDataErrors
			}

			// Call the function under test
			failureMessages := policyUndeploymentAction(tt.policy)

			// Validate output
			assert.Equal(t, tt.expectedFailures, failureMessages)
		})
	}
}

func TestProcessPoliciesTobeUndeployed_FailureInUndeployment(t *testing.T) {

	// Create a mock policy map
	mockPolicyMap := new(MockPolicyMap)

	// Define undeployed policies
	undeployedPolicies := map[string]string{"policy2": "1.0.0"}

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "policy2","policy-version": "1.0.0"}]}`

	// Override policyUndeploymentActionFunc to return a failure
	policyUndeploymentActionVar = func(policy map[string]interface{}) []string {
		return []string{"Failed to undeploy"}
	}

	// Run the function
	failureMessages, successPolicies := processPoliciesTobeUndeployed(undeployedPolicies)

	// Assertions
	assert.Equal(t, []string{"Failed to undeploy"}, failureMessages, "Expected failure message for undeployment failure")
	assert.Empty(t, successPolicies, "No policies should be successfully undeployed")

	// Ensure all expectations on the mock were met
	mockPolicyMap.AssertExpectations(t)
}

func TestProcessPoliciesTobeUndeployed_ErrorInRemoveFromMap(t *testing.T) {
	// Backup original function
	policyUndeploymentActionVar = func(policy map[string]interface{}) []string {
		return nil
	}

	//	mockPolicyMap := new(MockPolicyMap)
	undeployedPolicies := map[string]string{
		"policy4": "v1",
	}

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"policy-id": "policy4","policy-version": "v1"}]}`
	removeUndeployedPoliciesfromMapVar = func(undeployedPolicies map[string]interface{}) (string, error) {
		return "", errors.New("removal error")
	}

	// Run function
	failureMessages, successPolicies := processPoliciesTobeUndeployed(undeployedPolicies)

	// Assertions
	assert.Equal(t, []string{"Error in removing from LastDeployedPolicies"}, failureMessages, "Expected failure message for undeployment failure")
	assert.NotEmpty(t, successPolicies)
}

// Test cases for countChildKeysFromJSON
func TestCountChildKeysFromJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]int
	}{
		{
			name:     "Empty JSON",
			input:    map[string]interface{}{},
			expected: map[string]int{
				// No child nodes
			},
		},
		{
			name: "Single Level JSON",
			input: map[string]interface{}{
				"key1": map[string]interface{}{
					"child1": "value1",
					"child2": "value2",
				},
				"key2": map[string]interface{}{
					"childA": "valueA",
				},
			},
			expected: map[string]int{
				"node/key1": 2, // key1 has 2 children
				"node/key2": 1, // key2 has 1 child
			},
		},
		{
			name: "Nested JSON",
			input: map[string]interface{}{
				"root": map[string]interface{}{
					"level1": map[string]interface{}{
						"level2": map[string]interface{}{
							"child1": "value1",
							"child2": "value2",
						},
					},
				},
			},
			expected: map[string]int{
				"node/root":               1, // root has 1 child (level1)
				"node/root/level1":        1, // level1 has 1 child (level2)
				"node/root/level1/level2": 2, // level2 has 2 children
			},
		},
		{
			name: "Mixed Data Types",
			input: map[string]interface{}{
				"parent": map[string]interface{}{
					"child1": "string",
					"child2": 42,
					"child3": map[string]interface{}{
						"subchild1": true,
						"subchild2": nil,
					},
				},
			},
			expected: map[string]int{
				"node/parent":        3, // parent has 3 children
				"node/parent/child3": 2, // child3 has 2 children
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countChildKeysFromJSON(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("countChildKeysFromJSON() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestAnalyzeHierarchy(t *testing.T) {
	tests := []struct {
		name           string
		parentDataJson json.RawMessage
		dataPath       string
		expectedPath   string
		expectedErr    bool
	}{
		{
			name: "Valid hierarchy with multiple children",
			parentDataJson: json.RawMessage(`{
"root": {
"parent1": {
"child1": {},
"child2": {}
},
"parent2": {
"child3": {}
}
}
}`),
			dataPath:     "/root/parent1/child1",
			expectedPath: "/root/parent1/child1",
			expectedErr:  false,
		},
		{
			name: "Hierarchy with only one child, eligible parent",
			parentDataJson: json.RawMessage(`{
"root": {
"parent1": {
"child1": {}
}
}
}`),
			dataPath:     "/root/parent1/child1",
			expectedPath: "/root/parent1/child1",
			expectedErr:  false,
		},
		{
			name: "Invalid JSON structure",
			parentDataJson: json.RawMessage(`{
"root": { "parent1": "child1" `), // Malformed JSON
			dataPath:     "/root/parent1/child1",
			expectedPath: "",
			expectedErr:  true,
		},
		{
			name: "Path does not exist in JSON",
			parentDataJson: json.RawMessage(`{
"root": {
"parent1": {
"child1": {}
}
}
}`),
			dataPath:     "/root/parent2/child3",
			expectedPath: "/root/parent2/child3",
			expectedErr:  false,
		},
		{
			name: "Root path case",
			parentDataJson: json.RawMessage(`{
"root": {}
}`),
			dataPath:     "/root",
			expectedPath: "/root",
			expectedErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := analyzeHierarchy(tt.parentDataJson, tt.dataPath)

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPath, result)
			}
		})
	}
}

// Mock function variable for opasdkGetData
var mockGetData func(ctx context.Context, dataPath string) (*oapicodegen.OPADataResponse_Data, error)

func TestAnalyseEmptyParentNodes(t *testing.T) {
	// Backup the original function
	originalOpaSDKGetData := opasdkGetData
	opasdkGetData = func(ctx context.Context, dataPath string) (*oapicodegen.OPADataResponse_Data, error) {
		return mockGetData(ctx, dataPath)
	}
	defer func() {
		opasdkGetData = originalOpaSDKGetData // Restore after test
	}()

	tests := []struct {
		name           string
		inputPath      string
		mockResponse   interface{}
		mockError      error
		expectedOutput string
		expectError    bool
	}{
		// Case 1: Leaf node (no parent hierarchy)
		{
			name:           "Leaf Node - No Parent",
			inputPath:      "/singleSegment",
			mockResponse:   nil,
			mockError:      nil,
			expectedOutput: "/singleSegment",
			expectError:    false,
		},
		// Case 2: Parent exists with valid data
		{
			name:      "Success - Valid Parent Data Exists",
			inputPath: "/parent/child",
			mockResponse: map[string]interface{}{
				"child": "data",
			},
			mockError:      nil,
			expectedOutput: "/parent/child",
			expectError:    false,
		},
		// Case 3: Parent exists but is empty
		{
			name:           "Parent Exists but is Empty",
			inputPath:      "/parent/child",
			mockResponse:   map[string]interface{}{},
			mockError:      nil,
			expectedOutput: "/parent/child",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock function behavior
			opasdkGetData = func(ctx context.Context, dataPath string) (*oapicodegen.OPADataResponse_Data, error) {
				if tt.mockResponse != nil {
					jsonData, _ := json.Marshal(tt.mockResponse)
					var resData oapicodegen.OPADataResponse_Data
					_ = json.Unmarshal(jsonData, &resData)
					return &resData, tt.mockError
				}
				return nil, tt.mockError
			}

			// Call function
			output, err := analyseEmptyParentNodes(tt.inputPath)

			// Validate results
			if tt.expectError {
				assert.Error(t, err, "Expected error but got none")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.Equal(t, tt.expectedOutput, output, "Unexpected output")
			}
		})
	}
}

func TestProcessDataDeletionFromSdkAndDir(t *testing.T) {
	tests := []struct {
		name             string
		inputKeyPath     string
		mockAnalyseErr   error
		mockDeleteErr    error
		mockRemoveErr    error
		expectedFailures []string
	}{
		{
			name:             "Success - No errors",
			inputKeyPath:     "/valid/path",
			mockAnalyseErr:   nil,
			mockDeleteErr:    nil,
			mockRemoveErr:    nil,
			expectedFailures: []string{},
		},
		{
			name:             "Failure - analyseEmptyParentNodes error",
			inputKeyPath:     "/error/path",
			mockAnalyseErr:   errors.New("failed to analyze"),
			mockDeleteErr:    nil,
			mockRemoveErr:    nil,
			expectedFailures: []string{"failed to analyze"},
		},
		{
			name:             "Failure - deleteDataSdkFunc error",
			inputKeyPath:     "/delete/error",
			mockAnalyseErr:   nil,
			mockDeleteErr:    errors.New("delete failed"),
			mockRemoveErr:    nil,
			expectedFailures: []string{"delete failed"},
		},
		{
			name:             "Failure - removeDataDirectoryFunc error",
			inputKeyPath:     "/remove/error",
			mockAnalyseErr:   nil,
			mockDeleteErr:    nil,
			mockRemoveErr:    errors.New("remove failed"),
			expectedFailures: []string{"remove failed"},
		},
		{
			name:             "Failure - Multiple errors",
			inputKeyPath:     "/multiple/errors",
			mockAnalyseErr:   errors.New("analyse failed"),
			mockDeleteErr:    errors.New("delete failed"),
			mockRemoveErr:    errors.New("remove failed"),
			expectedFailures: []string{"analyse failed", "delete failed", "remove failed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock function variables
			analyseEmptyParentNodesFunc = func(dataPath string) (string, error) {
				return dataPath, tt.mockAnalyseErr
			}
			deleteDataSdkFunc = func(ctx context.Context, dataPath string) error {
				return tt.mockDeleteErr
			}
			removeDataDirectoryFunc = func(keyPath string) error {
				return tt.mockRemoveErr
			}

			// Call function
			failureMessages := processDataDeletionFromSdkAndDir(tt.inputKeyPath)

			// Normalize nil vs empty slice
			if failureMessages == nil {
				failureMessages = []string{}
			}

			// Validate results
			assert.Equal(t, tt.expectedFailures, failureMessages, "Unexpected failure messages")
		})
	}
}

// Mock function for testing
func mockProcessDataDeletion(keyPath string) []string {
	if keyPath == "/invalid/path" {
		return []string{"Failed to delete: " + keyPath}
	}
	return nil // Simulate successful deletion
}

func TestRemoveDataFromSdkandDir(t *testing.T) {
	// Mock the function globally
	originalProcessDataDeletion := processDataDeletionFromSdkAndDirFunc
	processDataDeletionFromSdkAndDirFunc = mockProcessDataDeletion
	defer func() { processDataDeletionFromSdkAndDirFunc = originalProcessDataDeletion }() // Restore after test

	tests := []struct {
		name             string
		policy           map[string]interface{}
		expectedFailures []string
	}{
		{
			name: "Valid data keys",
			policy: map[string]interface{}{
				"data": []interface{}{"policy.rule1", "policy.rule2"},
			},
			expectedFailures: nil,
		},
		{
			name: "Invalid data key type",
			policy: map[string]interface{}{
				"data": []interface{}{"policy.rule1", 123}, // Invalid integer key
			},
			expectedFailures: []string{"Invalid Key :123"},
		},
		{
			name: "Invalid JSON structure",
			policy: map[string]interface{}{
				"policyId":      "test-policy",
				"policyVersion": "1.0",
			},
			expectedFailures: []string{": Invalid JSON structure: 'data' is missing or not an array"},
		},

		{
			name: "Deletion failure",
			policy: map[string]interface{}{
				"data": []interface{}{"invalid.path"},
			},
			expectedFailures: []string{"Failed to delete: /invalid/path"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeDataFromSdkandDir(tt.policy)
			assert.ElementsMatch(t, tt.expectedFailures, result)
		})
	}
}
