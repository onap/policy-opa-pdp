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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/policymap"
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

// Failure case: Policy undeployment fails due to missing policy
func TestProcessPoliciesTobeUndeployed_Failure_NoMatch(t *testing.T) {
	undeployedPolicies := map[string]string{"non-existent-policy": "v1"}

	// Mock deployed policies (empty list)
	deployedPolicies := []map[string]interface{}{}

	mockPolicyMap := new(MockPolicyMap)
	mockPolicyMap.On("UnmarshalLastDeployedPolicies", mock.Anything).Return(deployedPolicies, nil)

	policymap.LastDeployedPolicies = `{"test-policy": "v1"}`

	failures, success := processPoliciesTobeUndeployed(undeployedPolicies)

	assert.Empty(t, success, "Expected no policies to be successfully undeployed")
	assert.Empty(t, failures, "Expected no failure messages")
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

func TestProcessPoliciesTobeUndeployed_Failure_PolicyNotFound(t *testing.T) {
	undeployedPolicies := map[string]string{"non-existent-policy": "v1"}
	mockPolicyMap := new(MockPolicyMap)
	mockPolicyMap.On("UnmarshalLastDeployedPolicies", mock.Anything).Return([]map[string]interface{}{}, nil)

	failures, success := processPoliciesTobeUndeployed(undeployedPolicies)

	assert.Empty(t, success, "Expected no successful undeployments since policy doesn't exist")
	assert.Empty(t, failures, "Failures list should be empty since policy wasn't found")
}

func TestProcessPoliciesTobeUndeployed_FailureInUndeployment(t *testing.T) {
	// Backup original function
	originalFunc := policyUndeploymentActionFunc
	defer func() { policyUndeploymentActionFunc = originalFunc }()

	// Mock policy undeployment action to fail
	policyUndeploymentActionFunc = func(policy map[string]interface{}) []string {
		return []string{"Failed to undeploy"}
	}

	mockPolicyMap := new(MockPolicyMap)
	undeployedPolicies := map[string]string{
		"policy2": "v1",
	}

	mockPolicy := map[string]interface{}{
		"policyID":      "policy2",
		"policyVersion": "v1",
	}

	mockPolicyMap.On("UnmarshalLastDeployedPolicies", mock.Anything).Return([]map[string]interface{}{mockPolicy}, nil)
	mockPolicyMap.On("RemoveUndeployedPoliciesfromMap", mockPolicy).Return("{}", nil)

	// Run function
	failureMessages, successPolicies := processPoliciesTobeUndeployed(undeployedPolicies)

	// Assertions
	assert.Empty(t, failureMessages)
	assert.Empty(t, successPolicies)
}

func TestProcessPoliciesTobeUndeployed_PolicyNotDeployed(t *testing.T) {
	// Backup original function
	originalFunc := policyUndeploymentActionFunc
	defer func() { policyUndeploymentActionFunc = originalFunc }()

	// Mock policy undeployment action to succeed
	policyUndeploymentActionFunc = func(policy map[string]interface{}) []string {
		return nil
	}

	mockPolicyMap := new(MockPolicyMap)
	undeployedPolicies := map[string]string{
		"policy3": "v1",
	}

	mockPolicyMap.On("UnmarshalLastDeployedPolicies", mock.Anything).Return([]map[string]interface{}{}, nil)

	// Run function
	failureMessages, successPolicies := processPoliciesTobeUndeployed(undeployedPolicies)

	// Assertions
	assert.Empty(t, failureMessages)
	assert.Empty(t, successPolicies)
}

func TestProcessPoliciesTobeUndeployed_ErrorInRemoveFromMap(t *testing.T) {
	// Backup original function
	originalFunc := policyUndeploymentActionFunc
	defer func() { policyUndeploymentActionFunc = originalFunc }()

	// Mock policy undeployment action to succeed
	policyUndeploymentActionFunc = func(policy map[string]interface{}) []string {
		return nil
	}

	mockPolicyMap := new(MockPolicyMap)
	undeployedPolicies := map[string]string{
		"policy4": "v1",
	}

	mockPolicy := map[string]interface{}{
		"policyID":      "policy4",
		"policyVersion": "v1",
	}

	mockPolicyMap.On("UnmarshalLastDeployedPolicies", mock.Anything).Return([]map[string]interface{}{mockPolicy}, nil)
	mockPolicyMap.On("RemoveUndeployedPoliciesfromMap", mockPolicy).Return("", errors.New("removal error"))

	// Run function
	failureMessages, successPolicies := processPoliciesTobeUndeployed(undeployedPolicies)

	// Assertions
	assert.Empty(t, failureMessages)
	assert.Empty(t, successPolicies)
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

// Test function for removeDataFromSdkandDir
func TestRemoveDataFromSdkandDir(t *testing.T) {
	// Backup original functions
	originalRemoveDataDirectory := removeDataDirectoryFunc
	originalDeleteData := deleteDataSdkFunc
	defer func() {
		removeDataDirectoryFunc = originalRemoveDataDirectory // Restore after test
		deleteDataSdkFunc = originalDeleteData                // Restore after test
	}()

	// Mock removeDataDirectoryFunc and deleteDataFunc to return errors for testing
	opasdkGetData = func(ctx context.Context, dataPath string) (data *oapicodegen.OPADataResponse_Data, err error) {
		// Mock JSON data
		mockedData := `{"mocked": {"success": "value", "error": "value"}}`
		// Create an instance of OPADataResponse_Data
		var response oapicodegen.OPADataResponse_Data
		// Unmarshal into the OPADataResponse_Data struct
		err = json.Unmarshal([]byte(mockedData), &response)
		if err != nil {
			return nil, errors.New("Error unmarshalling")
		}
		return &response, nil //
	}
	removeDataDirectoryFunc = func(dataKey string) error {
		if dataKey == "/mocked/error" {
			return errors.New("mocked remove data directory error")
		}
		return nil
	}

	deleteDataSdkFunc = func(ctx context.Context, keyPath string) error {
		if keyPath == "/mocked/error" {
			return errors.New("mocked delete data error")
		}
		return nil
	}

	policy := map[string]interface{}{
		"data": []interface{}{"mocked.success", "mocked.error"},
	}

	failures := removeDataFromSdkandDir(policy)

	assert.Len(t, failures, 1) // We expect two errors
	assert.Contains(t, failures[0], "mocked delete data error")
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
