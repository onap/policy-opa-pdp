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

// Package utils provides common  functionalities

package utils

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"strings"
)

// validates if the given request is in valid uuid form
func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// Helper function to create a directory if it doesn't exist
func CreateDirectory(dirPath string) error {
	err := os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		log.Errorf("Failed to create directory %s: %v", dirPath, err)
		return err
	}
	log.Infof("Directory created: %s", dirPath)
	return nil
}

// Helper function to check and remove a directory
func RemoveDirectory(dirPath string) error {

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warnf("Directory does not exist: %s", dirPath)
			// Directory does not exist, nothing to do
			return nil
		}
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		entryPath := filepath.Join(dirPath, entry.Name())

		if entry.IsDir() {
			// Check if the subdirectory is empty and delete it
			isEmpty, err := isDirEmpty(entryPath)
			if err != nil {
				return err
			}
			if isEmpty {
				log.Debugf("Removing empty subdirectory: %s", entryPath)
				if err := os.RemoveAll(entryPath); err != nil {
					return fmt.Errorf("failed to remove directory: %s, error: %w", entryPath, err)
				}
			}
		} else {
			// Delete specific files in the parent directory
			if entry.Name() == "data.json" || entry.Name() == "policy.rego" {
				log.Debugf("Removing file: %s", entryPath)
				if err := os.Remove(entryPath); err != nil {
					return fmt.Errorf("failed to remove file: %s, error: %w", entryPath, err)
				}
			}
		}
	}

	return nil
}

// Helper function to check if a directory is empty
func isDirEmpty(dirPath string) (bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return false, fmt.Errorf("failed to read directory: %s, error: %w", dirPath, err)
	}
	return len(entries) == 0, nil
}

func ValidateFieldsStructs(pdpUpdate model.PdpUpdate) error {
	//Initialize Validator and validate Struct after unmarshalling
	validate := validator.New()

	err := validate.Struct(pdpUpdate)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			log.Infof("Field %s failed on the %s tag\n", err.Field(), err.Tag())
		}
		return err
	}
	return err
}

// Validate validates the fields based on your requirements.
func ValidateToscaPolicyJsonFields(policy model.ToscaPolicy) error {
	// 1. Validate that Name, Version, and Metadata fields match.
	emphasize := "Validation emphasizes the condition"
	if policy.Name != policy.Metadata.PolicyID {
		return fmt.Errorf("policy name '%s' does not match metadata policy-id '%s', '%s'", policy.Name, policy.Metadata.PolicyID, emphasize)
	}
	if policy.Version != policy.Metadata.PolicyVersion {
		return fmt.Errorf("policy version '%s' does not match metadata policy-version '%s', '%s'", policy.Version, policy.Metadata.PolicyVersion, emphasize)
	}

	if policy.Properties.Data != nil {
		// 2. Validate that Name is a suffix for keys in Properties.Data and Properties.Policy.
		keySeen := make(map[string]bool)
		for key := range policy.Properties.Data {
			if keySeen[key] {
				return fmt.Errorf("duplicate data key '%s' found, '%s'", key, emphasize)
			}
			keySeen[key] = true
			if !strings.HasPrefix(key, policy.Name) {
				return fmt.Errorf("data key '%s' does not have name '%s' as a prefix, '%s'", key, policy.Name, emphasize)
			}
		}
	}
	keySeen := make(map[string]bool)
	for key := range policy.Properties.Policy {
		if keySeen[key] {
			return fmt.Errorf("duplicate policy key '%s' found, '%s'", key, emphasize)
		}
		keySeen[key] = true
		if !strings.HasPrefix(key, policy.Name) {
			return fmt.Errorf("policy key '%s' does not have name '%s' as a prefix, '%s'", key, policy.Name, emphasize)
		}
	}

	return nil
}

func IsPolicyNameAllowed(policy model.ToscaPolicy, deployedPolicies []map[string]interface{}) (bool, error) {

	policyID := policy.Name

	if policyID == "" {
		return false, fmt.Errorf("Policy Name cannot be Empty")
	}

	policyHierarchyLevel := strings.Split(policyID, ".")

	for _, deployedPolicy := range deployedPolicies {
		deployedPolicyID, ok := deployedPolicy["policy-id"].(string)
		if !ok {
			return false, fmt.Errorf("Invalid or missing policy-id field")
		}

		deployedPolicyIDHierarchyLevel := strings.Split(deployedPolicyID, ".")

		if isParentOfExistingPolicy(policyHierarchyLevel, deployedPolicyIDHierarchyLevel) {
			return false, fmt.Errorf("Policy Validation Failed : Policy-id: %s is parent  of deployed policy, overrides existing policy: %s", policyID, deployedPolicyID)
		}

		if isChildOfExistingPolicy(policyHierarchyLevel, deployedPolicyIDHierarchyLevel) {
			return false, fmt.Errorf("Policy Validation Failed:  Policy-id: %s is child  of deployed policy , can overwrite existing policy: %s", policyID, deployedPolicyID)

		}

	}

	return true, nil
}

func isParentOfExistingPolicy(policyHierarchyLevel, deployedPolicyIDHierarchyLevel []string) bool {

	// new policy should have fewer levels than deployed policy to be a parent
	if len(policyHierarchyLevel) < len(deployedPolicyIDHierarchyLevel) {
	for policyNameIndex := range policyHierarchyLevel {
		if policyHierarchyLevel[policyNameIndex] != deployedPolicyIDHierarchyLevel[policyNameIndex] {
			return false
		}
	}
	return true
	
        }

	return false
}

func isChildOfExistingPolicy(policyHierarchyLevel, deployedPolicyIDHierarchyLevel []string) bool {

	// new policy should have more levels than deployed policy to be a  child
	if len(policyHierarchyLevel) > len(deployedPolicyIDHierarchyLevel) {
	for policyNameIndex := range deployedPolicyIDHierarchyLevel {
		if deployedPolicyIDHierarchyLevel[policyNameIndex] != policyHierarchyLevel[policyNameIndex] {
			return false
		}
	}
	return true

        }

	return false
}
