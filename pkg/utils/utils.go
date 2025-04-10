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
        ValidateFieldsStructsFunc func(pdpUpdate model.PdpUpdate) error
)

var (
        CreateDirectoryVar CreateDirectoryFunc = CreateDirectory
        removeAll                              = os.RemoveAll
        ValidateFieldsStructsVar ValidateFieldsStructsFunc = ValidateFieldsStructs
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
		log.Debugf("Validating properties data for policy: %s", policy.Name)
		if err := validateDataKeys(policy.Properties.Data, "node."+policy.Name, "data", emphasize); err != nil {
			return err
		}
	}

	log.Debugf("Validating properties policy for policy: %s", policy.Name)
	if err := validatePolicyKeys(policy.Properties.Policy, policy.Name, "policy", emphasize); err != nil {
		return err
	}

	log.Infof("Validation successful for policy: %s", policy.Name)
	return nil
}

func validatePolicyKeys(policy map[string]string, prefix, propertyType, emphasize string) error {
	keySeen := make(map[string]bool)
	for key := range policy {
		if keySeen[key] {
			return fmt.Errorf("duplicate %s key '%s' found, '%s'", propertyType, key, emphasize)
		}
		keySeen[key] = true
		if !strings.HasPrefix(key, prefix) {
			return fmt.Errorf("%s key '%s' does not have name '%s' as a prefix, '%s'", propertyType, key, prefix, emphasize)
		}
	}
	return nil
}

func validateDataKeys(data map[string]string, prefix, propertyType, emphasize string) error {
	keySeen := make(map[string]bool)
	for key := range data {
		if keySeen[key] {
			return fmt.Errorf("duplicate %s key '%s' found, '%s'", propertyType, key, emphasize)
		}
		keySeen[key] = true
		if !strings.HasPrefix(key, prefix) {
			return fmt.Errorf("data key '%s' does not have name '%s' as a prefix", key, prefix)
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


type CommonFields struct {
	CurrentDate     *string
	CurrentDateTime *time.Time
	CurrentTime     *string
	TimeOffset      *string
	TimeZone        *string
	OnapComponent   *string
	OnapInstance    *string
	OnapName        *string
	PolicyName      string
}

func ValidateOPADataRequest(request interface{}) []string {
	//	var validationErrors []string

	if request == nil {
		return []string{"Request is nil"}
	}

	// Handle OPADataUpdateRequest validation
	if updateReq, ok := request.(*oapicodegen.OPADataUpdateRequest); ok {
		currentDate := ""
		if updateReq.CurrentDate != nil {
			currentDate = updateReq.CurrentDate.String()
		}

		commonFields := CommonFields{
                        CurrentDate: &currentDate, 
			CurrentDateTime: updateReq.CurrentDateTime, 
			CurrentTime: updateReq.CurrentTime, 
			TimeOffset: updateReq.TimeOffset, 
			TimeZone: updateReq.TimeZone, 
			OnapComponent: updateReq.OnapComponent, 
			OnapInstance: updateReq.OnapInstance, 
			OnapName: updateReq.OnapName, 
			PolicyName: convertPtrToString(updateReq.PolicyName),

		}
                return validateCommonFields(commonFields)

	}

	// Handle OPADecisionRequest validation
	if decisionReq, ok := request.(*oapicodegen.OPADecisionRequest); ok {
		currentDate := ""
		if decisionReq.CurrentDate != nil {
			currentDate = decisionReq.CurrentDate.String()
		}

		commonFields := CommonFields{
                        CurrentDate: &currentDate,
                        CurrentDateTime: decisionReq.CurrentDateTime,
                        CurrentTime: decisionReq.CurrentTime,
                        TimeOffset: decisionReq.TimeOffset,
                        TimeZone: decisionReq.TimeZone,
                        OnapComponent: decisionReq.OnapComponent,
                        OnapInstance: decisionReq.OnapInstance,
                        OnapName: decisionReq.OnapName,
                        PolicyName: decisionReq.PolicyName,
		}
		return validateCommonFields(commonFields)

	}
	return []string{"Invalid request type"}
}

func convertPtrToString(stringPtr *string) string {
	if stringPtr != nil {
		return *stringPtr
	}
	return ""

}

// Helper function to validate common fields
func validateCommonFields(fields CommonFields) []string {

	var validationErrors []string

	if fields.CurrentDate == nil || !IsValidCurrentDate(fields.CurrentDate) {
		validationErrors = append(validationErrors, "CurrentDate is invalid or missing")
	}
	if fields.CurrentDateTime == nil || !IsValidTime(fields.CurrentDateTime) {
		validationErrors = append(validationErrors, "CurrentDateTime is invalid or missing")
	}
	if fields.CurrentTime == nil || !IsValidCurrentTime(fields.CurrentTime) {
		validationErrors = append(validationErrors, "CurrentTime is invalid or missing")
	}
	if fields.TimeOffset == nil || !IsValidTimeOffset(fields.TimeOffset) {
		validationErrors = append(validationErrors, "TimeOffset is invalid or missing")
	}
	if fields.TimeZone == nil || !IsValidTimeZone(fields.TimeZone) {
		validationErrors = append(validationErrors, "TimeZone is invalid or missing")
	}
	if !IsValidString(fields.OnapComponent) {
		validationErrors = append(validationErrors, "OnapComponent is required")
	}
	if !IsValidString(fields.OnapInstance) {
		validationErrors = append(validationErrors, "OnapInstance is required")
	}
	if !IsValidString(fields.OnapName) {
		validationErrors = append(validationErrors, "OnapName is required")
	}
	if !IsValidString(fields.PolicyName) {
		validationErrors = append(validationErrors, "PolicyName is required and cannot be empty")
	}

	return validationErrors
}
