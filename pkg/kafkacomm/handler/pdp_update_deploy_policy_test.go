// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2025 Deutsche Telekom
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

package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"os"
	"os/exec"
	"path/filepath"
	"policy-opa-pdp/pkg/kafkacomm/publisher/mocks"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"strings"
	"testing"
)

func TestValidatePackageName(t *testing.T) {
	// Test cases
	tests := []struct {
		key                  string
		decodedPolicyContent string
		expectedError        bool
	}{
		{
			key:                  "mypackage",
			decodedPolicyContent: "package mypackage\n// Some comments",
			expectedError:        false,
		},
		{
			key:                  "mypackage",
			decodedPolicyContent: "",
			expectedError:        true, // Expecting an error due to no content
		},
		{
			key:                  "mypackage",
			decodedPolicyContent: " import fmt\n// No package declaration",
			expectedError:        true, // Expecting an error due to invalid package declaration
		},
		{
			key:                  "mypackage",
			decodedPolicyContent: "package anotherpackage\n// Wrong package name",
			expectedError:        true, // Expecting an error due to package name mismatch
		},
	}
	// Run each test case
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := validatePackageName(tt.key, tt.decodedPolicyContent)
			if tt.expectedError {
				assert.Error(t, err) // Expecting an error
			} else {
				assert.NoError(t, err) // Expecting no error
			}
		})
	}
}

func TestGetDirName(t *testing.T) {
	var testData = []struct {
		name     string
		policy   model.ToscaPolicy // Use the actual package name
		expected []string
	}{
		{
			name: "Basic valid case",
			policy: model.ToscaPolicy{
				Type:        "onap.policies.native.opa",
				TypeVersion: "1.0.0",
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
					Policy: map[string]string{
						"policy1": "value1",
						"policy2": "value2",
					},
				},
				Name:    "zone",
				Version: "1.0.0",
				Metadata: model.Metadata{
					PolicyID:      "zone",
					PolicyVersion: "1.0.0",
				},
			},
			expected: []string{
				"/opt/data/key2",
				"/opt/data/key1",
				"/opt/policies/policy1",
				"/opt/policies/policy2",
			},
		},
		{
			name: "Empty policy",
			policy: model.ToscaPolicy{
				Type:        "onap.policies.native.opa",
				TypeVersion: "1.0.0",
				Properties: model.PolicyProperties{
					Data:   map[string]string{},
					Policy: map[string]string{},
				},
				Name:    "zone",
				Version: "1.0.0",
				Metadata: model.Metadata{
					PolicyID:      "zone",
					PolicyVersion: "1.0.0",
				},
			},
			expected: []string{}, // No directories expected
		},
		{
			name: "Multiple keys",
			policy: model.ToscaPolicy{
				Type:        "onap.policies.native.opa",
				TypeVersion: "1.0.0",
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
					Policy: map[string]string{
						"policy1": "value1",
						"policy2": "value2",
					},
				},
				Name:    "zone",
				Version: "1.0.0",
				Metadata: model.Metadata{
					PolicyID:      "zone",
					PolicyVersion: "1.0.0",
				},
			},
			expected: []string{
				"/opt/data/key1",
				"/opt/data/key2",
				"/opt/policies/policy1",
				"/opt/policies/policy2",
			},
		},
		{
			name: "Special characters",
			policy: model.ToscaPolicy{
				Type:        "onap.policies.native.opa",
				TypeVersion: "1.0.0",
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"key.with.dot": "value1",
					},
					Policy: map[string]string{
						"policy.with.dot": "value2",
					},
				},
				Name:    "zone",
				Version: "1.0.0",
				Metadata: model.Metadata{
					PolicyID:      "zone",
					PolicyVersion: "1.0.0",
				},
			},
			expected: []string{
				"/opt/data/key/with/dot",
				"/opt/policies/policy/with/dot",
			},
		},
	}
	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			result := getDirName(tt.policy)
			// Check that the actual result is either nil or empty
			if len(tt.expected) == 0 {
				// They should both be empty
				assert.Empty(t, result) // Assert that result is empty
			} else {
				assert.ElementsMatch(t, tt.expected, result) // Standard equality check for non-empty scenarios
			}
		})
	}
}

func TestExtractAndDecodeData(t *testing.T) {
	tests := []struct {
		name         string
		policy       model.ToscaPolicy
		expectedData map[string]string
		expectedKeys []string
		expectError  bool
	}{
		{
			name: "Valid base64 data",
			policy: model.ToscaPolicy{
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"key1": base64.StdEncoding.EncodeToString([]byte("value1")),
						"key2": base64.StdEncoding.EncodeToString([]byte("value2")),
					},
				},
			},
			expectedData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectedKeys: []string{"key1", "key2"},
			expectError:  false,
		},
		{
			name: "Empty data map",
			policy: model.ToscaPolicy{
				Properties: model.PolicyProperties{
					Data: map[string]string{},
				},
			},
			expectedData: map[string]string{},
			expectedKeys: []string{},
			expectError:  false,
		},
		{
			name: "Invalid base64 data",
			policy: model.ToscaPolicy{
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"key1": "invalid_base64_data", // Not valid base64
					},
				},
			},
			expectedData: nil,
			expectedKeys: nil,
			expectError:  true, // We expect an error here
		},
		{
			name: "Multiple base64 entries",
			policy: model.ToscaPolicy{
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"key1": base64.StdEncoding.EncodeToString([]byte("value1")),
						"key2": base64.StdEncoding.EncodeToString([]byte("value2")),
						"key3": base64.StdEncoding.EncodeToString([]byte("value3")),
					},
				},
			},
			expectedData: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
			expectedKeys: []string{"key1", "key2", "key3"},
			expectError:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualData, actualKeys, err := extractAndDecodeData(tt.policy)
			if tt.expectError {
				require.Error(t, err) // Assert that an error occurred
				return
			} else {
				assert.NoError(t, err) // Ensure no error occurred
			}
			// Check the output against expected values
			assert.Equal(t, tt.expectedData, actualData)
			assert.ElementsMatch(t, tt.expectedKeys, actualKeys) // Use ElementsMatch for unordered comparison
		})
	}
}

// Test cases for extracting and decoding policies from a ToscaPolicy struct
func TestExtractAndDecodePolicies(t *testing.T) {
	tests := []struct {
		name             string
		policy           model.ToscaPolicy
		expectedPolicies map[string]string
		expectedKeys     []string
		expectError      bool
	}{
		{
			name: "Valid base64 policy",
			policy: model.ToscaPolicy{
				Properties: model.PolicyProperties{
					Policy: map[string]string{
						"policy1": base64.StdEncoding.EncodeToString([]byte("decoded policy content")),
					},
				},
			},
			expectedPolicies: map[string]string{
				"policy1": "decoded policy content",
			},
			expectedKeys: []string{"policy1"},
			expectError:  false,
		},
		{
			name: "Empty policy map",
			policy: model.ToscaPolicy{
				Properties: model.PolicyProperties{
					Policy: map[string]string{},
				},
			},
			expectedPolicies: map[string]string{},
			expectedKeys:     []string{},
			expectError:      false,
		},
		{
			name: "Invalid base64 policy",
			policy: model.ToscaPolicy{
				Properties: model.PolicyProperties{
					Policy: map[string]string{
						"policy1": "invalid_base64_data", // Not valid base64
					},
				},
			},
			expectedPolicies: nil,
			expectedKeys:     nil,
			expectError:      true,
		},
		{
			name: "Invalid package name validation",
			policy: model.ToscaPolicy{
				Properties: model.PolicyProperties{
					Policy: map[string]string{
						"invalidPolicy": base64.StdEncoding.EncodeToString([]byte("decoded policy content")),
					},
				},
			},
			expectedPolicies: nil,
			expectedKeys:     nil,
			expectError:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mocking the validatePackageName function
			var err error
			if tt.expectError && tt.name == "Invalid package name validation" {
				validatePackageNameVar = func(key, decodedPolicyContent string) error {
					return errors.New("package name validation failed")
				}
			} else {
				// Valid behavior for succeeding tests
				validatePackageNameVar = func(key, decodedPolicyContent string) error {
					return nil // No error for a valid package name
				}
			}
			actualPolicies, actualKeys, err := extractAndDecodePolicies(tt.policy)
			if tt.expectError {
				assert.Error(t, err) // We expect an error
			} else {
				assert.NoError(t, err) // We expect no error
				// Check the output against expected values
				assert.Equal(t, tt.expectedPolicies, actualPolicies)
				assert.ElementsMatch(t, tt.expectedKeys, actualKeys) // Compare keys
			}
		})
	}
}

func TestValidateParentPolicy(t *testing.T) {
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["cell.consis"],"policy": ["cell.consis"],"policy-id": "cdll.consis","policy-version": "1.0.0"},{"data": ["parent"],"policy": ["parent"],"policy-id": "parent.policy","policy-version": "1.0.0"}]}` // Reset to valid case
	tests := []struct {
		name       string
		input      model.ToscaPolicy
		expectPass bool
		expectErr  bool
	}{
		{
			name:       "Valid parent policy",
			input:      model.ToscaPolicy{Name: "zone"},
			expectPass: true,
			expectErr:  false,
		},
		{
			name:       "Valid child policy",
			input:      model.ToscaPolicy{Name: "parent.child.policy"},
			expectPass: true,
			expectErr:  false,
		},
		{
			name:       "Empty policy name",
			input:      model.ToscaPolicy{Name: ""},
			expectPass: false,
			expectErr:  true,
		},
		{
			name:       "Policy id not present",
			input:      model.ToscaPolicy{Name: "cell"},
			expectPass: false,
			expectErr:  true,
		},
		{
			name:       "Malformed last deployed policies",
			input:      model.ToscaPolicy{Name: "parent.policy"},
			expectPass: false,
			expectErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// If you want to test malformed policies, adjust policymap.LastDeployedPolicies accordingly
			if tt.name == "Malformed last deployed policies" {
				policymap.LastDeployedPolicies = `{"deployed_policies_dict": [}`
			} else if tt.name == "Policy id not present" {
				policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["parent"],"policy": ["parent"],"olicy-id": "parent.policy","policy-version": "1.0.0"}]}` // Reset to valid case
			}
			actualPass, actualErr := validateParentPolicy(tt.input)
			if tt.expectErr {
				assert.Error(t, actualErr)
			} else {
				assert.NoError(t, actualErr)
			}
			assert.Equal(t, tt.expectPass, actualPass)
		})
	}
}

func TestUpsertPolicyAndData_SuccessfulUpsert(t *testing.T) {
	policy := model.ToscaPolicy{
		Name: "TestPolicy",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"testPolicy": "encoded_value"},
			Data:   map[string]string{"testData": "encoded_data"},
		},
	}
	// Set mocks for this test only
	upsertPolicyFunc = func(model.ToscaPolicy) error { return nil }
	upsertDataFunc = func(model.ToscaPolicy) error { return nil }
	err := upsertPolicyAndData(policy, nil)
	assert.NoError(t, err)
}
func TestUpsertPolicyAndData_PolicyUpsertFailure(t *testing.T) {
	policy := model.ToscaPolicy{
		Name: "TestPolicy",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"testPolicy": "encoded_value"},
			Data:   map[string]string{"testData": "encoded_data"},
		},
	}
	// Set mock to simulate policy upsert failure
	upsertPolicyFunc = func(policy model.ToscaPolicy) error {
		return errors.New("mock policy upsert error")
	}
	upsertDataFunc = func(model.ToscaPolicy) error { return nil }
	err := upsertPolicyAndData(policy, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to Insert Policy")
}
func TestUpsertPolicyAndData_DataUpsertFailure(t *testing.T) {
	policy := model.ToscaPolicy{
		Name: "TestPolicy",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"testPolicy": "encoded_value"},
			Data:   map[string]string{"testData": "encoded_data"},
		},
	}
	// Set mocks for this test
	upsertPolicyFunc = func(model.ToscaPolicy) error { return nil }
	upsertDataFunc = func(model.ToscaPolicy) error { return errors.New("mock data upsert error") }
	err := upsertPolicyAndData(policy, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to Write Data")
}

func TestVerifyPolicyByBundleCreation(t *testing.T) {
	policy := model.ToscaPolicy{
		Name: "role",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"role": "cGFja2FnZSByb2xlCgppbXBvcnQgcmVnby52MQoKIyBCeSBkZWZhdWx0LCBkZW55IHJlcXVlc3RzLgpkZWZhdWx0IGFsbG93IDo9IGZhbHNlCgojIEFsbG93IGFkbWlucyB0byBkbyBhbnl0aGluZy4KYWxsb3cgaWYgdXNlcl9pc19hZG1pbgoKIyBBbGxvdyB0aGUgYWN0aW9uIGlmIHRoZSB1c2VyIGlzIGdyYW50ZWQgcGVybWlzc2lvbiB0byBwZXJmb3JtIHRoZSBhY3Rpb24uCmFsbG93IGlmIHsKICAgICAgICAjIEZpbmQgZ3JhbnRzIGZvciB0aGUgdXNlci4KICAgICAgICBzb21lIGdyYW50IGluIHVzZXJfaXNfZ3JhbnRlZAoKICAgICAgICAjIENoZWNrIGlmIHRoZSBncmFudCBwZXJtaXRzIHRoZSBhY3Rpb24uCiAgICAgICAgaW5wdXQuYWN0aW9uID09IGdyYW50LmFjdGlvbgogICAgICAgIGlucHV0LnR5cGUgPT0gZ3JhbnQudHlwZQp9CgojIHVzZXJfaXNfYWRtaW4gaXMgdHJ1ZSBpZiAiYWRtaW4iIGlzIGFtb25nIHRoZSB1c2VyJ3Mgcm9sZXMgYXMgcGVyIGRhdGEudXNlcl9yb2xlcwp1c2VyX2lzX2FkbWluIGlmICJhZG1pbiIgaW4gZGF0YS5yb2xlLnVzZXJfcm9sZXNbaW5wdXQudXNlcl0KCiMgdXNlcl9pc19ncmFudGVkIGlzIGEgc2V0IG9mIGdyYW50cyBmb3IgdGhlIHVzZXIgaWRlbnRpZmllZCBpbiB0aGUgcmVxdWVzdC4KIyBUaGUgYGdyYW50YCB3aWxsIGJlIGNvbnRhaW5lZCBpZiB0aGUgc2V0IGB1c2VyX2lzX2dyYW50ZWRgIGZvciBldmVyeS4uLgp1c2VyX2lzX2dyYW50ZWQgY29udGFpbnMgZ3JhbnQgaWYgewogICAgICAgICMgYHJvbGVgIGFzc2lnbmVkIGFuIGVsZW1lbnQgb2YgdGhlIHVzZXJfcm9sZXMgZm9yIHRoaXMgdXNlci4uLgogICAgICAgIHNvbWUgcm9sZSBpbiBkYXRhLnJvbGUudXNlcl9yb2xlc1tpbnB1dC51c2VyXQoKICAgICAgICAjIGBncmFudGAgYXNzaWduZWQgYSBzaW5nbGUgZ3JhbnQgZnJvbSB0aGUgZ3JhbnRzIGxpc3QgZm9yICdyb2xlJy4uLgogICAgICAgIHNvbWUgZ3JhbnQgaW4gZGF0YS5yb2xlLnJvbGVfZ3JhbnRzW3JvbGVdCn0KCiMgICAgICAgKiBSZWdvIGNvbXBhcmlzb24gdG8gb3RoZXIgc3lzdGVtczogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC9jb21wYXJpc29uLXRvLW90aGVyLXN5c3RlbXMvCiMgICAgICAgKiBSZWdvIEl0ZXJhdGlvbjogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC8jaXRlcmF0aW9uCgo="},
			Data:   map[string]string{"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K"},
		},
	}

	//Mocking the CreateBundle
	createBundleFuncVar = func(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error) {
		return "", nil
	}
	err := verifyPolicyByBundleCreation(policy)
	assert.NoError(t, err)

}

func TestVerifyPolicyByBundleCreation_getDirEmpty(t *testing.T) {
	policy := model.ToscaPolicy{
		Name: "role",
		Properties: model.PolicyProperties{
			Policy: map[string]string{},
			Data:   map[string]string{},
		},
	}

	//Mocking the CreateBundle
	//    createBundleFuncVar = func(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error){ return "", nil}
	err := verifyPolicyByBundleCreation(policy)
	assert.Error(t, err)

}

func TestVerifyPolicyByBundleCreation_BundleFailure(t *testing.T) {
	policy := model.ToscaPolicy{
		Name: "role",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"role": "cGFja2FnZSByb2xlCgppbXBvcnQgcmVnby52MQoKIyBCeSBkZWZhdWx0LCBkZW55IHJlcXVlc3RzLgpkZWZhdWx0IGFsbG93IDo9IGZhbHNlCgojIEFsbG93IGFkbWlucyB0byBkbyBhbnl0aGluZy4KYWxsb3cgaWYgdXNlcl9pc19hZG1pbgoKIyBBbGxvdyB0aGUgYWN0aW9uIGlmIHRoZSB1c2VyIGlzIGdyYW50ZWQgcGVybWlzc2lvbiB0byBwZXJmb3JtIHRoZSBhY3Rpb24uCmFsbG93IGlmIHsKICAgICAgICAjIEZpbmQgZ3JhbnRzIGZvciB0aGUgdXNlci4KICAgICAgICBzb21lIGdyYW50IGluIHVzZXJfaXNfZ3JhbnRlZAoKICAgICAgICAjIENoZWNrIGlmIHRoZSBncmFudCBwZXJtaXRzIHRoZSBhY3Rpb24uCiAgICAgICAgaW5wdXQuYWN0aW9uID09IGdyYW50LmFjdGlvbgogICAgICAgIGlucHV0LnR5cGUgPT0gZ3JhbnQudHlwZQp9CgojIHVzZXJfaXNfYWRtaW4gaXMgdHJ1ZSBpZiAiYWRtaW4iIGlzIGFtb25nIHRoZSB1c2VyJ3Mgcm9sZXMgYXMgcGVyIGRhdGEudXNlcl9yb2xlcwp1c2VyX2lzX2FkbWluIGlmICJhZG1pbiIgaW4gZGF0YS5yb2xlLnVzZXJfcm9sZXNbaW5wdXQudXNlcl0KCiMgdXNlcl9pc19ncmFudGVkIGlzIGEgc2V0IG9mIGdyYW50cyBmb3IgdGhlIHVzZXIgaWRlbnRpZmllZCBpbiB0aGUgcmVxdWVzdC4KIyBUaGUgYGdyYW50YCB3aWxsIGJlIGNvbnRhaW5lZCBpZiB0aGUgc2V0IGB1c2VyX2lzX2dyYW50ZWRgIGZvciBldmVyeS4uLgp1c2VyX2lzX2dyYW50ZWQgY29udGFpbnMgZ3JhbnQgaWYgewogICAgICAgICMgYHJvbGVgIGFzc2lnbmVkIGFuIGVsZW1lbnQgb2YgdGhlIHVzZXJfcm9sZXMgZm9yIHRoaXMgdXNlci4uLgogICAgICAgIHNvbWUgcm9sZSBpbiBkYXRhLnJvbGUudXNlcl9yb2xlc1tpbnB1dC51c2VyXQoKICAgICAgICAjIGBncmFudGAgYXNzaWduZWQgYSBzaW5nbGUgZ3JhbnQgZnJvbSB0aGUgZ3JhbnRzIGxpc3QgZm9yICdyb2xlJy4uLgogICAgICAgIHNvbWUgZ3JhbnQgaW4gZGF0YS5yb2xlLnJvbGVfZ3JhbnRzW3JvbGVdCn0KCiMgICAgICAgKiBSZWdvIGNvbXBhcmlzb24gdG8gb3RoZXIgc3lzdGVtczogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC9jb21wYXJpc29uLXRvLW90aGVyLXN5c3RlbXMvCiMgICAgICAgKiBSZWdvIEl0ZXJhdGlvbjogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC8jaXRlcmF0aW9uCgo="},
			Data:   map[string]string{"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K"},
		},
	}

	//Mocking the CreateBundle
	createBundleFuncVar = func(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error) {
		return "", errors.New("Fail to Initialize Bundle")
	}
	err := verifyPolicyByBundleCreation(policy)
	assert.Error(t, err)

}

func TestCheckIfPolicyAlreadyDeployed_PolicymapEmpty(t *testing.T) {

	// Sample data for testing
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{Name: "TestPolicy1"},
			{Name: "TestPolicy2"},
		},
	}
	// Test case 1: No deployed policies
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": []}` // Simulating an empty LastDeployedPolicies
	result := checkIfPolicyAlreadyDeployed(pdpUpdate)
	assert.Equal(t, pdpUpdate.PoliciesToBeDeployed, result)
}

func TestCheckIfPolicyAlreadyDeployed_ExistingPolicy(t *testing.T) {

	// Sample data for testing
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{Name: "TestPolicy1", Version: "1.0.0"},
			{Name: "TestPolicy2", Version: "1.0.0"},
		},
	}
	// Test case 1: No deployed policies
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["cell.consis"],"policy": ["cell.consis"],"policy-id": "cdll.consis","policy-version": "1.0.0"},{"data": ["parent"],"policy": ["parent"],"policy-id": "TestPolicy1","policy-version": "1.0.0"}]}` // Reset to valid case
	result := checkIfPolicyAlreadyDeployed(pdpUpdate)
	assert.NotEqual(t, pdpUpdate.PoliciesToBeDeployed, result)
}

func TestCreateAndStorePolicyData_Success(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name: "role",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"role": "cGFja2FnZSByb2xlCgppbXBvcnQgcmVnby52MQoKIyBCeSBkZWZhdWx0LCBkZW55IHJlcXVlc3RzLgpkZWZhdWx0IGFsbG93IDo9IGZhbHNlCgojIEFsbG93IGFkbWlucyB0byBkbyBhbnl0aGluZy4KYWxsb3cgaWYgdXNlcl9pc19hZG1pbgoKIyBBbGxvdyB0aGUgYWN0aW9uIGlmIHRoZSB1c2VyIGlzIGdyYW50ZWQgcGVybWlzc2lvbiB0byBwZXJmb3JtIHRoZSBhY3Rpb24uCmFsbG93IGlmIHsKICAgICAgICAjIEZpbmQgZ3JhbnRzIGZvciB0aGUgdXNlci4KICAgICAgICBzb21lIGdyYW50IGluIHVzZXJfaXNfZ3JhbnRlZAoKICAgICAgICAjIENoZWNrIGlmIHRoZSBncmFudCBwZXJtaXRzIHRoZSBhY3Rpb24uCiAgICAgICAgaW5wdXQuYWN0aW9uID09IGdyYW50LmFjdGlvbgogICAgICAgIGlucHV0LnR5cGUgPT0gZ3JhbnQudHlwZQp9CgojIHVzZXJfaXNfYWRtaW4gaXMgdHJ1ZSBpZiAiYWRtaW4iIGlzIGFtb25nIHRoZSB1c2VyJ3Mgcm9sZXMgYXMgcGVyIGRhdGEudXNlcl9yb2xlcwp1c2VyX2lzX2FkbWluIGlmICJhZG1pbiIgaW4gZGF0YS5yb2xlLnVzZXJfcm9sZXNbaW5wdXQudXNlcl0KCiMgdXNlcl9pc19ncmFudGVkIGlzIGEgc2V0IG9mIGdyYW50cyBmb3IgdGhlIHVzZXIgaWRlbnRpZmllZCBpbiB0aGUgcmVxdWVzdC4KIyBUaGUgYGdyYW50YCB3aWxsIGJlIGNvbnRhaW5lZCBpZiB0aGUgc2V0IGB1c2VyX2lzX2dyYW50ZWRgIGZvciBldmVyeS4uLgp1c2VyX2lzX2dyYW50ZWQgY29udGFpbnMgZ3JhbnQgaWYgewogICAgICAgICMgYHJvbGVgIGFzc2lnbmVkIGFuIGVsZW1lbnQgb2YgdGhlIHVzZXJfcm9sZXMgZm9yIHRoaXMgdXNlci4uLgogICAgICAgIHNvbWUgcm9sZSBpbiBkYXRhLnJvbGUudXNlcl9yb2xlc1tpbnB1dC51c2VyXQoKICAgICAgICAjIGBncmFudGAgYXNzaWduZWQgYSBzaW5nbGUgZ3JhbnQgZnJvbSB0aGUgZ3JhbnRzIGxpc3QgZm9yICdyb2xlJy4uLgogICAgICAgIHNvbWUgZ3JhbnQgaW4gZGF0YS5yb2xlLnJvbGVfZ3JhbnRzW3JvbGVdCn0KCiMgICAgICAgKiBSZWdvIGNvbXBhcmlzb24gdG8gb3RoZXIgc3lzdGVtczogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC9jb21wYXJpc29uLXRvLW90aGVyLXN5c3RlbXMvCiMgICAgICAgKiBSZWdvIEl0ZXJhdGlvbjogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC8jaXRlcmF0aW9uCgo="},
			Data:   map[string]string{"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K"},
		},
	}

	// Assign mock functions
	extractAndDecodePoliciesVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) { return nil, []string{}, nil }
	createPolicyDirectoriesVar = func(map[string]string) error { return nil }
	createDataDirectoriesVar = func(map[string]string) error { return nil }
	// Call function under test
	err := createAndStorePolicyData(policy)
	// Verify no errors
	assert.NoError(t, err)
}

func TestCreateAndStorePolicyData_FailToExtract(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name: "role",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"role": "cGFja2FnZSByb2xlCgppbXBvcnQgcmVnby52MQoKIyBCeSBkZWZhdWx0LCBkZW55IHJlcXVlc3RzLgpkZWZhdWx0IGFsbG93IDo9IGZhbHNlCgojIEFsbG93IGFkbWlucyB0byBkbyBhbnl0aGluZy4KYWxsb3cgaWYgdXNlcl9pc19hZG1pbgoKIyBBbGxvdyB0aGUgYWN0aW9uIGlmIHRoZSB1c2VyIGlzIGdyYW50ZWQgcGVybWlzc2lvbiB0byBwZXJmb3JtIHRoZSBhY3Rpb24uCmFsbG93IGlmIHsKICAgICAgICAjIEZpbmQgZ3JhbnRzIGZvciB0aGUgdXNlci4KICAgICAgICBzb21lIGdyYW50IGluIHVzZXJfaXNfZ3JhbnRlZAoKICAgICAgICAjIENoZWNrIGlmIHRoZSBncmFudCBwZXJtaXRzIHRoZSBhY3Rpb24uCiAgICAgICAgaW5wdXQuYWN0aW9uID09IGdyYW50LmFjdGlvbgogICAgICAgIGlucHV0LnR5cGUgPT0gZ3JhbnQudHlwZQp9CgojIHVzZXJfaXNfYWRtaW4gaXMgdHJ1ZSBpZiAiYWRtaW4iIGlzIGFtb25nIHRoZSB1c2VyJ3Mgcm9sZXMgYXMgcGVyIGRhdGEudXNlcl9yb2xlcwp1c2VyX2lzX2FkbWluIGlmICJhZG1pbiIgaW4gZGF0YS5yb2xlLnVzZXJfcm9sZXNbaW5wdXQudXNlcl0KCiMgdXNlcl9pc19ncmFudGVkIGlzIGEgc2V0IG9mIGdyYW50cyBmb3IgdGhlIHVzZXIgaWRlbnRpZmllZCBpbiB0aGUgcmVxdWVzdC4KIyBUaGUgYGdyYW50YCB3aWxsIGJlIGNvbnRhaW5lZCBpZiB0aGUgc2V0IGB1c2VyX2lzX2dyYW50ZWRgIGZvciBldmVyeS4uLgp1c2VyX2lzX2dyYW50ZWQgY29udGFpbnMgZ3JhbnQgaWYgewogICAgICAgICMgYHJvbGVgIGFzc2lnbmVkIGFuIGVsZW1lbnQgb2YgdGhlIHVzZXJfcm9sZXMgZm9yIHRoaXMgdXNlci4uLgogICAgICAgIHNvbWUgcm9sZSBpbiBkYXRhLnJvbGUudXNlcl9yb2xlc1tpbnB1dC51c2VyXQoKICAgICAgICAjIGBncmFudGAgYXNzaWduZWQgYSBzaW5nbGUgZ3JhbnQgZnJvbSB0aGUgZ3JhbnRzIGxpc3QgZm9yICdyb2xlJy4uLgogICAgICAgIHNvbWUgZ3JhbnQgaW4gZGF0YS5yb2xlLnJvbGVfZ3JhbnRzW3JvbGVdCn0KCiMgICAgICAgKiBSZWdvIGNvbXBhcmlzb24gdG8gb3RoZXIgc3lzdGVtczogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC9jb21wYXJpc29uLXRvLW90aGVyLXN5c3RlbXMvCiMgICAgICAgKiBSZWdvIEl0ZXJhdGlvbjogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC8jaXRlcmF0aW9uCgo="},
			Data:   map[string]string{"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K"},
		},
	}

	//Mocking the CreateBundle
	// Assign mock functions
	extractAndDecodePoliciesVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) {
		return nil, []string{}, errors.New("Failure in extracting")
	}
	// Call function under test
	err := createAndStorePolicyData(policy)
	// Verify no errors
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failure in extracting")
}

func TestCreateAndStorePolicyData_FailToCreatePolicyDirectories(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name: "role",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"role": "cGFja2FnZSByb2xlCgppbXBvcnQgcmVnby52MQoKIyBCeSBkZWZhdWx0LCBkZW55IHJlcXVlc3RzLgpkZWZhdWx0IGFsbG93IDo9IGZhbHNlCgojIEFsbG93IGFkbWlucyB0byBkbyBhbnl0aGluZy4KYWxsb3cgaWYgdXNlcl9pc19hZG1pbgoKIyBBbGxvdyB0aGUgYWN0aW9uIGlmIHRoZSB1c2VyIGlzIGdyYW50ZWQgcGVybWlzc2lvbiB0byBwZXJmb3JtIHRoZSBhY3Rpb24uCmFsbG93IGlmIHsKICAgICAgICAjIEZpbmQgZ3JhbnRzIGZvciB0aGUgdXNlci4KICAgICAgICBzb21lIGdyYW50IGluIHVzZXJfaXNfZ3JhbnRlZAoKICAgICAgICAjIENoZWNrIGlmIHRoZSBncmFudCBwZXJtaXRzIHRoZSBhY3Rpb24uCiAgICAgICAgaW5wdXQuYWN0aW9uID09IGdyYW50LmFjdGlvbgogICAgICAgIGlucHV0LnR5cGUgPT0gZ3JhbnQudHlwZQp9CgojIHVzZXJfaXNfYWRtaW4gaXMgdHJ1ZSBpZiAiYWRtaW4iIGlzIGFtb25nIHRoZSB1c2VyJ3Mgcm9sZXMgYXMgcGVyIGRhdGEudXNlcl9yb2xlcwp1c2VyX2lzX2FkbWluIGlmICJhZG1pbiIgaW4gZGF0YS5yb2xlLnVzZXJfcm9sZXNbaW5wdXQudXNlcl0KCiMgdXNlcl9pc19ncmFudGVkIGlzIGEgc2V0IG9mIGdyYW50cyBmb3IgdGhlIHVzZXIgaWRlbnRpZmllZCBpbiB0aGUgcmVxdWVzdC4KIyBUaGUgYGdyYW50YCB3aWxsIGJlIGNvbnRhaW5lZCBpZiB0aGUgc2V0IGB1c2VyX2lzX2dyYW50ZWRgIGZvciBldmVyeS4uLgp1c2VyX2lzX2dyYW50ZWQgY29udGFpbnMgZ3JhbnQgaWYgewogICAgICAgICMgYHJvbGVgIGFzc2lnbmVkIGFuIGVsZW1lbnQgb2YgdGhlIHVzZXJfcm9sZXMgZm9yIHRoaXMgdXNlci4uLgogICAgICAgIHNvbWUgcm9sZSBpbiBkYXRhLnJvbGUudXNlcl9yb2xlc1tpbnB1dC51c2VyXQoKICAgICAgICAjIGBncmFudGAgYXNzaWduZWQgYSBzaW5nbGUgZ3JhbnQgZnJvbSB0aGUgZ3JhbnRzIGxpc3QgZm9yICdyb2xlJy4uLgogICAgICAgIHNvbWUgZ3JhbnQgaW4gZGF0YS5yb2xlLnJvbGVfZ3JhbnRzW3JvbGVdCn0KCiMgICAgICAgKiBSZWdvIGNvbXBhcmlzb24gdG8gb3RoZXIgc3lzdGVtczogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC9jb21wYXJpc29uLXRvLW90aGVyLXN5c3RlbXMvCiMgICAgICAgKiBSZWdvIEl0ZXJhdGlvbjogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC8jaXRlcmF0aW9uCgo="},
			Data:   map[string]string{"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K"},
		},
	}

	//Mocking the CreateBundle
	extractAndDecodePoliciesVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) { return nil, []string{}, nil }
	createPolicyDirectoriesVar = func(map[string]string) error { return errors.New("failed to create directories") }
	// Call function under test
	err := createAndStorePolicyData(policy)
	// Verify error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create directories")
}

func TestCreateAndStorePolicyData_FailToExtractData(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name: "role",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"role": "cGFja2FnZSByb2xlCgppbXBvcnQgcmVnby52MQoKIyBCeSBkZWZhdWx0LCBkZW55IHJlcXVlc3RzLgpkZWZhdWx0IGFsbG93IDo9IGZhbHNlCgojIEFsbG93IGFkbWlucyB0byBkbyBhbnl0aGluZy4KYWxsb3cgaWYgdXNlcl9pc19hZG1pbgoKIyBBbGxvdyB0aGUgYWN0aW9uIGlmIHRoZSB1c2VyIGlzIGdyYW50ZWQgcGVybWlzc2lvbiB0byBwZXJmb3JtIHRoZSBhY3Rpb24uCmFsbG93IGlmIHsKICAgICAgICAjIEZpbmQgZ3JhbnRzIGZvciB0aGUgdXNlci4KICAgICAgICBzb21lIGdyYW50IGluIHVzZXJfaXNfZ3JhbnRlZAoKICAgICAgICAjIENoZWNrIGlmIHRoZSBncmFudCBwZXJtaXRzIHRoZSBhY3Rpb24uCiAgICAgICAgaW5wdXQuYWN0aW9uID09IGdyYW50LmFjdGlvbgogICAgICAgIGlucHV0LnR5cGUgPT0gZ3JhbnQudHlwZQp9CgojIHVzZXJfaXNfYWRtaW4gaXMgdHJ1ZSBpZiAiYWRtaW4iIGlzIGFtb25nIHRoZSB1c2VyJ3Mgcm9sZXMgYXMgcGVyIGRhdGEudXNlcl9yb2xlcwp1c2VyX2lzX2FkbWluIGlmICJhZG1pbiIgaW4gZGF0YS5yb2xlLnVzZXJfcm9sZXNbaW5wdXQudXNlcl0KCiMgdXNlcl9pc19ncmFudGVkIGlzIGEgc2V0IG9mIGdyYW50cyBmb3IgdGhlIHVzZXIgaWRlbnRpZmllZCBpbiB0aGUgcmVxdWVzdC4KIyBUaGUgYGdyYW50YCB3aWxsIGJlIGNvbnRhaW5lZCBpZiB0aGUgc2V0IGB1c2VyX2lzX2dyYW50ZWRgIGZvciBldmVyeS4uLgp1c2VyX2lzX2dyYW50ZWQgY29udGFpbnMgZ3JhbnQgaWYgewogICAgICAgICMgYHJvbGVgIGFzc2lnbmVkIGFuIGVsZW1lbnQgb2YgdGhlIHVzZXJfcm9sZXMgZm9yIHRoaXMgdXNlci4uLgogICAgICAgIHNvbWUgcm9sZSBpbiBkYXRhLnJvbGUudXNlcl9yb2xlc1tpbnB1dC51c2VyXQoKICAgICAgICAjIGBncmFudGAgYXNzaWduZWQgYSBzaW5nbGUgZ3JhbnQgZnJvbSB0aGUgZ3JhbnRzIGxpc3QgZm9yICdyb2xlJy4uLgogICAgICAgIHNvbWUgZ3JhbnQgaW4gZGF0YS5yb2xlLnJvbGVfZ3JhbnRzW3JvbGVdCn0KCiMgICAgICAgKiBSZWdvIGNvbXBhcmlzb24gdG8gb3RoZXIgc3lzdGVtczogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC9jb21wYXJpc29uLXRvLW90aGVyLXN5c3RlbXMvCiMgICAgICAgKiBSZWdvIEl0ZXJhdGlvbjogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC8jaXRlcmF0aW9uCgo="},
			Data:   map[string]string{"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K"},
		},
	}

	//Mocking the CreateBundle
	// Assign mock functions
	extractAndDecodePoliciesVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) { return nil, []string{}, nil }
	createPolicyDirectoriesVar = func(map[string]string) error { return nil }
	extractAndDecodeDataVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) {
		return nil, []string{}, errors.New("data extraction error")
	}
	// Call function under test
	err := createAndStorePolicyData(policy)
	// Verify error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data extraction error")
}
func TestCreateAndStorePolicyData_FailToCreateDataDirectories(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name: "role",
		Properties: model.PolicyProperties{
			Policy: map[string]string{"role": "cGFja2FnZSByb2xlCgppbXBvcnQgcmVnby52MQoKIyBCeSBkZWZhdWx0LCBkZW55IHJlcXVlc3RzLgpkZWZhdWx0IGFsbG93IDo9IGZhbHNlCgojIEFsbG93IGFkbWlucyB0byBkbyBhbnl0aGluZy4KYWxsb3cgaWYgdXNlcl9pc19hZG1pbgoKIyBBbGxvdyB0aGUgYWN0aW9uIGlmIHRoZSB1c2VyIGlzIGdyYW50ZWQgcGVybWlzc2lvbiB0byBwZXJmb3JtIHRoZSBhY3Rpb24uCmFsbG93IGlmIHsKICAgICAgICAjIEZpbmQgZ3JhbnRzIGZvciB0aGUgdXNlci4KICAgICAgICBzb21lIGdyYW50IGluIHVzZXJfaXNfZ3JhbnRlZAoKICAgICAgICAjIENoZWNrIGlmIHRoZSBncmFudCBwZXJtaXRzIHRoZSBhY3Rpb24uCiAgICAgICAgaW5wdXQuYWN0aW9uID09IGdyYW50LmFjdGlvbgogICAgICAgIGlucHV0LnR5cGUgPT0gZ3JhbnQudHlwZQp9CgojIHVzZXJfaXNfYWRtaW4gaXMgdHJ1ZSBpZiAiYWRtaW4iIGlzIGFtb25nIHRoZSB1c2VyJ3Mgcm9sZXMgYXMgcGVyIGRhdGEudXNlcl9yb2xlcwp1c2VyX2lzX2FkbWluIGlmICJhZG1pbiIgaW4gZGF0YS5yb2xlLnVzZXJfcm9sZXNbaW5wdXQudXNlcl0KCiMgdXNlcl9pc19ncmFudGVkIGlzIGEgc2V0IG9mIGdyYW50cyBmb3IgdGhlIHVzZXIgaWRlbnRpZmllZCBpbiB0aGUgcmVxdWVzdC4KIyBUaGUgYGdyYW50YCB3aWxsIGJlIGNvbnRhaW5lZCBpZiB0aGUgc2V0IGB1c2VyX2lzX2dyYW50ZWRgIGZvciBldmVyeS4uLgp1c2VyX2lzX2dyYW50ZWQgY29udGFpbnMgZ3JhbnQgaWYgewogICAgICAgICMgYHJvbGVgIGFzc2lnbmVkIGFuIGVsZW1lbnQgb2YgdGhlIHVzZXJfcm9sZXMgZm9yIHRoaXMgdXNlci4uLgogICAgICAgIHNvbWUgcm9sZSBpbiBkYXRhLnJvbGUudXNlcl9yb2xlc1tpbnB1dC51c2VyXQoKICAgICAgICAjIGBncmFudGAgYXNzaWduZWQgYSBzaW5nbGUgZ3JhbnQgZnJvbSB0aGUgZ3JhbnRzIGxpc3QgZm9yICdyb2xlJy4uLgogICAgICAgIHNvbWUgZ3JhbnQgaW4gZGF0YS5yb2xlLnJvbGVfZ3JhbnRzW3JvbGVdCn0KCiMgICAgICAgKiBSZWdvIGNvbXBhcmlzb24gdG8gb3RoZXIgc3lzdGVtczogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC9jb21wYXJpc29uLXRvLW90aGVyLXN5c3RlbXMvCiMgICAgICAgKiBSZWdvIEl0ZXJhdGlvbjogaHR0cHM6Ly93d3cub3BlbnBvbGljeWFnZW50Lm9yZy9kb2NzL2xhdGVzdC8jaXRlcmF0aW9uCgo="},
			Data:   map[string]string{"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K"},
		},
	}

	//Mocking the CreateBundle
	// Assign mock functions
	extractAndDecodePoliciesVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) { return nil, []string{}, nil }
	createPolicyDirectoriesVar = func(map[string]string) error { return nil }
	extractAndDecodeDataVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) { return nil, []string{}, nil }
	createDataDirectoriesVar = func(map[string]string) error { return errors.New("failed to create data directories") }
	// Call function under test
	err := createAndStorePolicyData(policy)
	// Verify error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create data directories")
}

func TestHandlePolicyDeployment_Success(t *testing.T) {

	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{
				Properties: model.PolicyProperties{
					Data: map[string]string{
					        "node.role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
					Policy: map[string]string{
						"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
				},
				Name:    "role",
				Version: "1.0",
				Metadata: model.Metadata{
					PolicyID:      "role",
					PolicyVersion: "1.0",
				},
			},
		},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
		Name:                   "Test Pdp Update",
	}
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	//Mocking fucntions
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{}]}` // Reset to valid case
	createAndStorePolicyDataVar = func(policy model.ToscaPolicy) error { return nil }
	createBundleFuncVar = func(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error) {
		return "", nil
	}
	validateParentPolicyVar = func(policy model.ToscaPolicy) (bool, error) { return true, nil }
	upsertPolicyFunc = func(model.ToscaPolicy) error { return nil }
	upsertDataFunc = func(model.ToscaPolicy) error { return nil }

	err, _ := handlePolicyDeployment(pdpUpdate, mockSender)
	assert.Nil(t, err)
}

func TestHandlePolicyDeployment_ValidateTosca(t *testing.T) {

	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"node.role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
					Policy: map[string]string{
						"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
				},
				Name:    "role",
				Version: "1.0",
				Metadata: model.Metadata{
					PolicyID:      "role2",
					PolicyVersion: "1.0",
				},
			},
		},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
		Name:                   "Test Pdp Update",
	}
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{}]}` // Reset to valid case
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	err, _ := handlePolicyDeployment(pdpUpdate, mockSender)
	found := false
	for _, message := range err {
		if strings.Contains(message, "Tosca Policy Validation failed") {
			found = true
			break
		}
	}
	assert.True(t, found, "Error Message Doesn't Match")
}

func TestHandlePolicyDeployment_ValidateParent(t *testing.T) {

	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"node.role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
					Policy: map[string]string{
						"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
				},
				Name:    "role",
				Version: "1.0",
				Metadata: model.Metadata{
					PolicyID:      "role",
					PolicyVersion: "1.0",
				},
			},
		},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
		Name:                   "Test Pdp Update",
	}
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["role.hello"],"policy": ["role.hello"],"policy-id": "role.hello","policy-version": "1.0.0"}]}` // Reset to valid case
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	validateParentPolicyVar = func(policy model.ToscaPolicy) (bool, error) {
		return false, errors.New("parent policy already present")
	}
	err, _ := handlePolicyDeployment(pdpUpdate, mockSender)
	found := false
	for _, message := range err {
		if strings.Contains(message, "parent policy already present") {
			found = true
			break
		}
	}
	assert.True(t, found, "Error Message Doesn't Match")
}

func TestHandlePolicyDeployment_StorePolicyDataFailure(t *testing.T) {

	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"node.role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
					Policy: map[string]string{
						"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
				},
				Name:    "role",
				Version: "1.0",
				Metadata: model.Metadata{
					PolicyID:      "role",
					PolicyVersion: "1.0",
				},
			},
		},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
		Name:                   "Test Pdp Update",
	}
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	//Mocking fucntions
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{}]}` // Reset to valid case
	createAndStorePolicyDataVar = func(policy model.ToscaPolicy) error { return errors.New("Failure in StorePolicyData") }
	validateParentPolicyVar = func(policy model.ToscaPolicy) (bool, error) { return true, nil }
	err, _ := handlePolicyDeployment(pdpUpdate, mockSender)
	found := false
	for _, message := range err {
		if strings.Contains(message, "Failure in StorePolicyData") {
			found = true
			break
		}
	}
	assert.True(t, found, "Error Message Doesn't Match")
}

func TestHandlePolicyDeployment_VerifyBundleFailure(t *testing.T) {

	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"node.role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
					Policy: map[string]string{
						"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
				},
				Name:    "role",
				Version: "1.0",
				Metadata: model.Metadata{
					PolicyID:      "role",
					PolicyVersion: "1.0",
				},
			},
		},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
		Name:                   "Test Pdp Update",
	}
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	//Mocking fucntions
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{}]}` // Reset to valid case
	createAndStorePolicyDataVar = func(policy model.ToscaPolicy) error { return nil }
	validateParentPolicyVar = func(policy model.ToscaPolicy) (bool, error) { return true, nil }
	createBundleFuncVar = func(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error) {
		return "", errors.New("Failed to Bundle")
	}
	err, _ := handlePolicyDeployment(pdpUpdate, mockSender)
	found := false
	for _, message := range err {
		if strings.Contains(message, "Failed to Bundle") {
			found = true
			break
		}
	}
	assert.True(t, found, "Error Message Doesn't Match")
}

func TestHandlePolicyDeployment_upsertPolicyAndDataFailure(t *testing.T) {

	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{
				Properties: model.PolicyProperties{
					Data: map[string]string{
						"node.role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
					Policy: map[string]string{
						"role": "ewogICAgInVzZXJfcm9sZXMiOiB7CiAgICAgICAgImFsaWNlIjogWwogICAgICAgICAgICAiYWRtaW4iCiAgICAgICAgXSwKICAgICAgICAiYm9iIjogWwogICAgICAgICAgICAiZW1wbG95ZWUiLAogICAgICAgICAgICAiYmlsbGluZyIKICAgICAgICBdLAogICAgICAgICJldmUiOiBbCiAgICAgICAgICAgICJjdXN0b21lciIKICAgICAgICBdCiAgICB9LAogICAgInJvbGVfZ3JhbnRzIjogewogICAgICAgICJjdXN0b21lciI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImNhdCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJhZG9wdCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAiYWRvcHQiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiZW1wbG95ZWUiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJkb2ciCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAicmVhZCIsCiAgICAgICAgICAgICAgICAidHlwZSI6ICJjYXQiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImRvZyIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJ1cGRhdGUiLAogICAgICAgICAgICAgICAgInR5cGUiOiAiY2F0IgogICAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYmlsbGluZyI6IFsKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgImFjdGlvbiI6ICJyZWFkIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJhY3Rpb24iOiAidXBkYXRlIiwKICAgICAgICAgICAgICAgICJ0eXBlIjogImZpbmFuY2UiCiAgICAgICAgICAgIH0KICAgICAgICBdCiAgICB9Cn0K",
					},
				},
				Name:    "role",
				Version: "1.0",
				Metadata: model.Metadata{
					PolicyID:      "role",
					PolicyVersion: "1.0",
				},
			},
		},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
		Name:                   "Test Pdp Update",
	}
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	//Mocking fucntions
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{}]}` // Reset to valid case
	createAndStorePolicyDataVar = func(policy model.ToscaPolicy) error { return nil }
	validateParentPolicyVar = func(policy model.ToscaPolicy) (bool, error) { return true, nil }
	createBundleFuncVar = func(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error) {
		return "", nil
	}
	upsertPolicyFunc = func(model.ToscaPolicy) error { return errors.New("SDKError") }
	err, _ := handlePolicyDeployment(pdpUpdate, mockSender)
	found := false
	for _, message := range err {
		if strings.Contains(message, "SDKError") {
			found = true
			break
		}
	}
	assert.True(t, found, "Error Message Doesn't Match")
}

func TestCreatePolicyDirectories_testing(t *testing.T) {
	// Create a temporary directory under /tmp
	basePolicyDir = "test_policy_dirs"
	err := os.MkdirAll(basePolicyDir, os.ModePerm)
	assert.NoError(t, err, "Failed to create base policy directory")
	defer os.RemoveAll(basePolicyDir) // Cleanup after the test
	// Example decoded policies to test
	decodedPolicies := map[string]string{
		"test.policy":    "package test\n\nsome_rule = true",
		"another.policy": "package another\n\nanother_rule = false",
	}
	// Call the function to test
	utils.CreateDirectoryVar = func(dirPath string) error { os.MkdirAll(dirPath, os.ModePerm); return nil }
	err = createPolicyDirectories(decodedPolicies)
	// Assertions
	assert.NoError(t, err, "Expected no error during policy directory creation")
	// Verify that directories and files were created
	for key := range decodedPolicies {
		policyDir := filepath.Join(basePolicyDir, filepath.Join(strings.Split(key, ".")...))
		// Check if the directory was created
		_, err := os.Stat(policyDir)
		assert.NoError(t, err, "Expected policy directory to be created: %s", policyDir)
		// Check if the policy.rego file was created
		policyFile := filepath.Join(policyDir, "policy.rego")
		_, err = os.Stat(policyFile)
		assert.NoError(t, err, "Expected policy file to be created: %s", policyFile)
	}
}

func TestCreatePolicyDirectories_testingFailure(t *testing.T) {
	// Create a temporary directory under /tmp
	basePolicyDir = "test_policy_dirs"
	err := os.MkdirAll(basePolicyDir, os.ModePerm)
	assert.NoError(t, err, "Failed to create base policy directory")
	defer os.RemoveAll(basePolicyDir) // Cleanup after the test
	// Example decoded policies to test
	decodedPolicies := map[string]string{
		"test.policy":    "package test\n\nsome_rule = true",
		"another.policy": "package another\n\nanother_rule = false",
	}
	// Call the function to test
	utils.CreateDirectoryVar = func(dirPath string) error { return errors.New("Fail to Create Dir") }
	err = createPolicyDirectories(decodedPolicies)
	// Assertions
	assert.Error(t, err, "Expected no error during policy directory creation")
}

func TestCreatePolicyDirectories_testingSaveFailure(t *testing.T) {
	// Create a temporary directory under /tmp
	basePolicyDir = "test_policy_dirs"
	err := os.MkdirAll(basePolicyDir, os.ModePerm)
	assert.NoError(t, err, "Failed to create base policy directory")
	defer os.RemoveAll(basePolicyDir) // Cleanup after the test
	// Example decoded policies to test
	decodedPolicies := map[string]string{
		"test.policy":    "package test\n\nsome_rule = true",
		"another.policy": "package another\n\nanother_rule = false",
	}
	// Call the function to test
	utils.CreateDirectoryVar = func(dirPath string) error { return nil }
	err = createPolicyDirectories(decodedPolicies)
	// Assertions
	assert.Error(t, err, "Expected no error during policy directory creation")
}

func TestCreateDataDirectories_testing(t *testing.T) {
	// Create a temporary directory under /tmp
	baseDataDir = "test_policy_dirs"
	err := os.MkdirAll(basePolicyDir, os.ModePerm)
	assert.NoError(t, err, "Failed to create base policy directory")
	defer os.RemoveAll(basePolicyDir) // Cleanup after the test
	// Example decoded policies to test
	decodedPolicies := map[string]string{
		"test.policy":    "package test\n\nsome_rule = true",
		"another.policy": "package another\n\nanother_rule = false",
	}
	// Call the function to test
	utils.CreateDirectoryVar = func(dirPath string) error { os.MkdirAll(dirPath, os.ModePerm); return nil }
	err = createDataDirectories(decodedPolicies)
	// Assertions
	assert.NoError(t, err, "Expected no error during policy directory creation")
	// Verify that directories and files were created
	for key := range decodedPolicies {
		policyDir := filepath.Join(basePolicyDir, filepath.Join(strings.Split(key, ".")...))
		// Check if the directory was created
		_, err := os.Stat(policyDir)
		assert.NoError(t, err, "Expected policy directory to be created: %s", policyDir)
		// Check if the policy.rego file was created
		policyFile := filepath.Join(policyDir, "data.json")
		_, err = os.Stat(policyFile)
		assert.NoError(t, err, "Expected policy file to be created: %s", policyFile)
	}
}

func TestCreateDataDirectories_testingFailure(t *testing.T) {
	// Create a temporary directory under /tmp
	baseDataDir = "test_policy_dirs"
	err := os.MkdirAll(basePolicyDir, os.ModePerm)
	assert.NoError(t, err, "Failed to create base policy directory")
	defer os.RemoveAll(basePolicyDir) // Cleanup after the test
	// Example decoded policies to test
	decodedPolicies := map[string]string{
		"test.policy":    "package test\n\nsome_rule = true",
		"another.policy": "package another\n\nanother_rule = false",
	}
	// Call the function to test
	utils.CreateDirectoryVar = func(dirPath string) error { return errors.New("Fail to Create Dir") }
	err = createDataDirectories(decodedPolicies)
	// Assertions
	assert.Error(t, err, "Expected no error during policy directory creation")
}

func TestCreateDataDirectories_testingSaveFailure(t *testing.T) {
	// Create a temporary directory under /tmp
	baseDataDir = "test_policy_dirs"
	err := os.MkdirAll(basePolicyDir, os.ModePerm)
	assert.NoError(t, err, "Failed to create base policy directory")
	defer os.RemoveAll(basePolicyDir) // Cleanup after the test
	// Example decoded policies to test
	decodedPolicies := map[string]string{
		"test.policy":    "package test\n\nsome_rule = true",
		"another.policy": "package another\n\nanother_rule = false",
	}
	// Call the function to test
	utils.CreateDirectoryVar = func(dirPath string) error { return nil }
	err = createDataDirectories(decodedPolicies)
	// Assertions
	assert.Error(t, err, "Expected no error during policy directory creation")
}

// Test function for upsertPolicy
func TestUpsertPolicy(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name:    "TestPolicy",
		Version: "1.0.0",
		Properties: model.PolicyProperties{
			Policy: map[string]string{
				"policy1": base64.StdEncoding.EncodeToString([]byte("package policy1\ndecoded policy content")),
			},
			Data: map[string]string{
				"key1": base64.StdEncoding.EncodeToString([]byte("value1")),
				"key2": base64.StdEncoding.EncodeToString([]byte("value2")),
			},
		},
	}
	//mocking Functions
	extractAndDecodePoliciesVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) {
		return map[string]string{"policy1": "Policy De"}, []string{"policy1"}, nil
	}
	opasdk.UpsertPolicyVar = func(ctx context.Context, policyID string, policyContent []byte) error { return nil }
	// Call the function under test
	err := upsertPolicy(policy)
	// Test assertions
	assert.NoError(t, err, "Expected no error during policy upsert")
}

// Test for failure in UpsertPolicy
func TestUpsertPolicy_Failure(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name:    "TestPolicy",
		Version: "1.0.0",
		Properties: model.PolicyProperties{
			Policy: map[string]string{
				"policy1": base64.StdEncoding.EncodeToString([]byte("package policy1\ndecoded policy content")),
			},
			Data: map[string]string{
				"key1": base64.StdEncoding.EncodeToString([]byte("value1")),
				"key2": base64.StdEncoding.EncodeToString([]byte("value2")),
			},
		},
	}
	//mocking Functions
	extractAndDecodePoliciesVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) {
		return map[string]string{"policy1": "Policy De"}, []string{"policy1"}, nil
	}
	opasdk.UpsertPolicyVar = func(ctx context.Context, policyID string, policyContent []byte) error {
		return errors.New("Failure in Upsert SDK")
	}
	// Call the function under test
	err := upsertPolicy(policy)
	// Testn assertions
	assert.Error(t, err)
}

// Test function for upsertPolicy
func TestUpsertData(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name:    "TestPolicy",
		Version: "1.0.0",
		Properties: model.PolicyProperties{
			Policy: map[string]string{
				"policy1": base64.StdEncoding.EncodeToString([]byte("package policy1\ndecoded policy content")),
			},
			Data: map[string]string{
				"key1": base64.StdEncoding.EncodeToString([]byte("value1")),
				"key2": base64.StdEncoding.EncodeToString([]byte("value2")),
			},
		},
	}
	//mocking Functions
	extractAndDecodeDataVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) {
		return map[string]string{"policy1": "{\"user_roles\": {\"alice\": [\"admin\"],\"bob\": [\"employee\",\"billing\"],\"eve\": [\"customer\"]}}"}, []string{"policy1"}, nil
	}
	opasdk.WriteDataVar = func(ctx context.Context, dataPath string, data interface{}) error { return nil }
	// Call the function under test
	err := upsertData(policy)
	// Test assertions
	assert.NoError(t, err)
}

// Test for failure in UpsertPolicy
func TestUpsertData_Failure(t *testing.T) {
	// Sample Tosca Policy
	policy := model.ToscaPolicy{
		Name:    "TestPolicy",
		Version: "1.0.0",
		Properties: model.PolicyProperties{
			Policy: map[string]string{
				"policy1": base64.StdEncoding.EncodeToString([]byte("package policy1\ndecoded policy content")),
			},
			Data: map[string]string{
				"key1": base64.StdEncoding.EncodeToString([]byte("value1")),
				"key2": base64.StdEncoding.EncodeToString([]byte("value2")),
			},
		},
	}
	//mocking Functions
	extractAndDecodeDataVar = func(policy model.ToscaPolicy) (map[string]string, []string, error) {
		return map[string]string{"policy1": "{\"user_roles\": {\"alice\": [\"admin\"],\"bob\": [\"employee\",\"billing\"],\"eve\": [\"customer\"]}}"}, []string{"policy1"}, nil
	}
	opasdk.WriteDataVar = func(ctx context.Context, dataPath string, data interface{}) error {
		return errors.New("Failure in Write Data in SDK")
	}
	// Call the function under test
	err := upsertData(policy)
	// Testn assertions
	assert.Error(t, err)
}
