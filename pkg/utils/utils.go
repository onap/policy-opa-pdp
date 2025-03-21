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

// Package provides common  functionalities

package utils

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"os"
	"os/exec"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"regexp"
	"strings"
	"time"
)

type (
	CreateDirectoryFunc func(dirPath string) error
)

var (
	CreateDirectoryVar CreateDirectoryFunc = CreateDirectory
	removeAll                              = os.RemoveAll
)

// validates if the given request is in valid uuid form
func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// Helper function to create a directory if it doesn't exist
func CreateDirectory(dirPath string) error {
	err := os.MkdirAll(dirPath, 0750)
	if err != nil {
		log.Errorf("Failed to create directory %s: %v", dirPath, err)
		return err
	}
	log.Infof("Directory created: %s", dirPath)
	return nil
}

// Helper function to check and remove a directory
func RemoveDirectory(dirPath string) error {

	fileDirPath := filepath.Clean(dirPath)
	err := removeAll(fileDirPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warnf("Directory does not exist: %s", fileDirPath)
			// Directory does not exist, nothing to do
			return nil
		}
		return fmt.Errorf("failed to remove file: %s, error: %w", fileDirPath, err)

	}

	// Create a loop to check parent directories.
	// Move to the parent directory
	currentPath := filepath.Clean(filepath.Dir(dirPath))
	for {
		// Check if we have reached the match path
		if currentPath == filepath.Clean(consts.DataNode) || currentPath == filepath.Clean(consts.Policies) {
			return nil // Stop if we reach the match path
		}

		if currentPath == "/" || currentPath == "." {
			log.Infof("Reached root orelative path: %s", currentPath)
			return nil // Stop if we reach the match path
		}
		log.Infof("Processig Parent dir : %s", currentPath)
		// Check if the parent directory exists before proceeding
		if _, err := os.Stat(currentPath); os.IsNotExist(err) {
			log.Debugf("directory does not exist: %s. Stopping iteration.", currentPath)
			return nil // Stop if we can't find the parent path
		}
		// Clean the parent directory
		err = isSubDirEmpty(currentPath)
		if err != nil {
			return err
		}

		// Move to the parent directory
		currentPath = filepath.Dir(currentPath)
	}
}

func isSubDirEmpty(entryPath string) error {

	isEmpty, err := isDirEmpty(entryPath)
	if err != nil {
		return err
	}
	if isEmpty {
		log.Debugf("Removing empty subdirectory: %s", entryPath)
		if err := removeAll(entryPath); err != nil {
			return fmt.Errorf("failed to remove directory: %s, error: %w", entryPath, err)
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
			if !strings.HasPrefix(key, "node."+policy.Name) {
				return fmt.Errorf("data key '%s' does not have name node.'%s' as a prefix, '%s'", key, policy.Name, emphasize)
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

// Custom validation function for time format
func IsValidTime(t *time.Time) bool {
	if t == nil {
		return false
	}
	// Format the time in RFC3339 and try parsing it
	formattedTime := t.Format(time.RFC3339)
	// Check if the time is a valid date
	_, err := time.Parse(time.RFC3339, formattedTime)
	return err == nil
}

// Custom validation function for time offset format (e.g., '02:00', '-05:00')
func IsValidTimeOffset(offset *string) bool {
	if offset == nil || strings.TrimSpace(*offset) == "" {
		return false
	}
	re := regexp.MustCompile(`^[-+]?(0\d|1\d|2[0-3]):[0-5]\d$`) // Format like 02:00, -05:00
	return re.MatchString(*offset)
}

// Custom validation function for IANA time zone format (e.g., 'America/New_York')
func IsValidTimeZone(zone *string) bool {
	if zone == nil || strings.TrimSpace(*zone) == "" {
		return false
	}
	_, err := time.LoadLocation(*zone) // Check if it's a real timezone
	if err != nil {
		return false
	}
	re := regexp.MustCompile(`^(?:[A-Za-z]+(?:/[A-Za-z_]+)?|UTC([+-]\d{1,2}:?\d{2})?|[A-Za-z]{3,4})$`) //^(?:[A-Za-z]/[A-Za-z_]|UTC)$`) // Simple check for time zone format like 'America/New_York' or UTC etc
	return re.MatchString(*zone)
}

// Custom validation function for data input
func IsValidData(data *[]map[string]interface{}) bool {
	if data == nil || len(*data) == 0 {
		return false
	} else {
		return true
	}
}

// Custom validation function for CurrentDate
func IsValidCurrentDate(currentDate *string) bool {
	if currentDate == nil || strings.TrimSpace(*currentDate) == "" {
		return false
	}
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`) //  eg: "2025-01-17"
	return re.MatchString(*currentDate)
}

// Custom validation function for CurrentTime
func IsValidCurrentTime(currentTime *string) bool {
	if currentTime == nil || strings.TrimSpace(*currentTime) == "" {
		return false
	}
	re := regexp.MustCompile(`^\d{2}:\d{2}:\d{2}\.\d{3}Z$`) //eg: 08:26:41.857Z
	return re.MatchString(*currentTime)
}

// Custom validation function for *string type eg: OnapComponent, OnapInstance, OnapName, PolicyName
func IsValidString(name interface{}) bool {
	switch v := name.(type) {
	case *string:
		return v != nil && strings.TrimSpace(*v) != ""
	case string:
		return strings.TrimSpace(v) != ""
	default:
		return false // Handles cases where name is neither a string nor a *string
	}
}

func BuildBundle(cmdFunc func(string, ...string) *exec.Cmd) (string, error) {
	cmd := cmdFunc(
		consts.Opa,
		consts.BuildBundle,
		consts.V1Compatible,
		consts.Policies,
		consts.Data,
		consts.Output,
		consts.BundleTarGzFile,
	)
	log.Debugf("Before calling combinedoutput")
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Warnf("Error output : %s", string(output))
		log.Warnf("Failed to build Bundle: %v", err)
		return string(output), err
	}
	log.Debug("Bundle Built Sucessfully....")
	return string(output), nil
}

// Validation function
func ValidateOPADataRequest(request interface{}) []string {
	var validationErrors []string
	if updateRequest, ok := request.(*oapicodegen.OPADataUpdateRequest); ok {
		if updateRequest == nil { // Check if updateRequest is nil
			validationErrors = append(validationErrors, "OPADataUpdateRequest is nil")
			return validationErrors // Return if the request is nil
		}
		// Check if required fields are populated
		if updateRequest.CurrentDate != nil {
			dateString := updateRequest.CurrentDate.String()
			if !IsValidCurrentDate(&dateString) {
				validationErrors = append(validationErrors, "CurrentDate is invalid")
			}
		} else {
			validationErrors = append(validationErrors, "CurrentDate is required")
		}

		// Validate CurrentDateTime format
		if !(IsValidTime(updateRequest.CurrentDateTime)) {
			validationErrors = append(validationErrors, "CurrentDateTime is invalid or missing")
		}

		// Validate CurrentTime format
		if !(IsValidCurrentTime(updateRequest.CurrentTime)) {
			validationErrors = append(validationErrors, "CurrentTime is invalid or missing")
		}

		// Validate TimeOffset format (e.g., +02:00 or -05:00)
		if !(IsValidTimeOffset(updateRequest.TimeOffset)) {
			validationErrors = append(validationErrors, "TimeOffset is invalid or missing")
		}

		// Validate TimeZone format (e.g., 'America/New_York')
		if !(IsValidTimeZone(updateRequest.TimeZone)) {
			validationErrors = append(validationErrors, "TimeZone is invalid or missing")
		}

		// Optionally, check if 'OnapComponent', 'OnapInstance', 'OnapName', and 'PolicyName' are provided
		if !(IsValidString(updateRequest.OnapComponent)) {
			validationErrors = append(validationErrors, "OnapComponent is required")
		}

		if !(IsValidString(updateRequest.OnapInstance)) {
			validationErrors = append(validationErrors, "OnapInstance is required")
		}

		if !(IsValidString(updateRequest.OnapName)) {
			validationErrors = append(validationErrors, "OnapName is required")
		}

		if !(IsValidString(updateRequest.PolicyName)) {
			validationErrors = append(validationErrors, "PolicyName is required and cannot be empty")
		}
	}

	if decisionRequest, ok := request.(*oapicodegen.OPADecisionRequest); ok {

		if decisionRequest == nil { // Check if decisionRequest is nil
			validationErrors = append(validationErrors, "OPADecisionRequest is nil")
			return validationErrors // Return if the request is nil
		}
		// Check if required fields are populated
		if decisionRequest.CurrentDate != nil {
			dateString := decisionRequest.CurrentDate.String()
			if !IsValidCurrentDate(&dateString) {
				validationErrors = append(validationErrors, "CurrentDate is invalid")
			}
		}

		// Validate CurrentDateTime format
		if (decisionRequest.CurrentDateTime != nil) && !(IsValidTime(decisionRequest.CurrentDateTime)) {
			validationErrors = append(validationErrors, "CurrentDateTime is invalid or missing")
		}

		// Validate CurrentTime format
		if (decisionRequest.CurrentTime != nil) && !(IsValidCurrentTime(decisionRequest.CurrentTime)) {
			validationErrors = append(validationErrors, "CurrentTime is invalid or missing")
		}

		// Validate TimeOffset format (e.g., +02:00 or -05:00)
		if (decisionRequest.TimeOffset != nil) && !(IsValidTimeOffset(decisionRequest.TimeOffset)) {
			validationErrors = append(validationErrors, "TimeOffset is invalid or missing")
		}

		// Validate TimeZone format (e.g., 'America/New_York')
		if (decisionRequest.TimeZone != nil) && !(IsValidTimeZone(decisionRequest.TimeZone)) {
			validationErrors = append(validationErrors, "TimeZone is invalid or missing")
		}

		// Optionally, check if 'OnapComponent', 'OnapInstance', 'OnapName', and 'PolicyName' are provided
		if (decisionRequest.OnapComponent != nil) && !(IsValidString(decisionRequest.OnapComponent)) {
			validationErrors = append(validationErrors, "OnapComponent is required")
		}

		if (decisionRequest.OnapInstance != nil) && !(IsValidString(decisionRequest.OnapInstance)) {
			validationErrors = append(validationErrors, "OnapInstance is required")
		}

		if (decisionRequest.OnapName != nil) && !(IsValidString(decisionRequest.OnapName)) {
			validationErrors = append(validationErrors, "OnapName is required")
		}

		if !(IsValidString(decisionRequest.PolicyName)) {
			validationErrors = append(validationErrors, "PolicyName is required and cannot be empty")
		}
	}
	return validationErrors
}
