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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"sort"
	"strings"
)

// Define types for the functions
type (
	UpsertPolicyFunc             func(model.ToscaPolicy) error
	UpsertDataFunc               func(model.ToscaPolicy) error
	HandlePolicyDeploymentFunc   func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string)
	validatePackageNameFunc      func(key, decodedPolicyContent string) error
	extractAndDecodePoliciesFunc func(policy model.ToscaPolicy) (map[string]string, []string, error)
	createPolicyDirectoriesFunc  func(decodedPolicies map[string]string) error
	extractAndDecodeDatFunc      func(policy model.ToscaPolicy) (map[string]string, []string, error)
	createDataDirectoriesFunc    func(decodedData map[string]string) error
	createAndStorePolicyDataFunc func(policy model.ToscaPolicy) error
	validateParentPolicyFunc     func(policy model.ToscaPolicy) (bool, error)
)

// Declare function variables that will be used during testing
var (
	upsertPolicyFunc            UpsertPolicyFunc             = upsertPolicy
	upsertDataFunc              UpsertDataFunc               = upsertData
	handlePolicyDeploymentVar   HandlePolicyDeploymentFunc   = handlePolicyDeployment
	validatePackageNameVar      validatePackageNameFunc      = validatePackageName
	extractAndDecodePoliciesVar extractAndDecodePoliciesFunc = extractAndDecodePolicies
	createPolicyDirectoriesVar  createPolicyDirectoriesFunc  = createPolicyDirectories
	extractAndDecodeDataVar     extractAndDecodeDatFunc      = extractAndDecodeData
	createDataDirectoriesVar    createDataDirectoriesFunc    = createDataDirectories
	createAndStorePolicyDataVar createAndStorePolicyDataFunc = createAndStorePolicyData
	validateParentPolicyVar     validateParentPolicyFunc     = validateParentPolicy
)

// stores policy and data files to directory.
func createAndStorePolicyData(policy model.ToscaPolicy) error {

	// Extract and decode policies
	decodedPolicies, key, err := extractAndDecodePoliciesVar(policy)
	if err != nil {
		log.Errorf("Failed to extract and decode policies for key : %v, %v", key, err)
		return err
	}

	err = createPolicyDirectoriesVar(decodedPolicies)
	if err != nil {
		log.Errorf("Failed to create policy directories: %v", err)
		return err
	}

	decodedData, key, err := extractAndDecodeDataVar(policy)
	if err != nil {
		log.Errorf("Failed to extract and decode data: %v", err)
		return err
	}

	err = createDataDirectoriesVar(decodedData)
	if err != nil {
		log.Errorf("Failed to create data directories: %v", err)
		return err
	}

	return nil
}

// Function to create directories and save policies
func createPolicyDirectories(decodedPolicies map[string]string) error {

	for key, decodedPolicy := range decodedPolicies {
		policyDir := filepath.Join(basePolicyDir, filepath.Join(strings.Split(key, ".")...))

		err := utils.CreateDirectoryVar(policyDir)
		if err != nil {
			log.Errorf("Failed to create policy directory %s: %v", policyDir, err)
			return err
		}

		err = os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(decodedPolicy), 0600)
		if err != nil {
			log.Errorf("Failed to save policy.rego for %s: %v", key, err)
			return err
		}
		log.Infof("Policy file saved: %s", filepath.Join(policyDir, "policy.rego"))
	}

	return nil
}

// Function to create directories and save data
func createDataDirectories(decodedData map[string]string) error {

	for key, dataContent := range decodedData {
		dataDir := filepath.Join(baseDataDir, filepath.Join(strings.Split(key, ".")...))

		err := utils.CreateDirectoryVar(dataDir)
		if err != nil {
			log.Errorf("Failed to create data directory %s: %v", dataDir, err)
			return err
		}

		err = os.WriteFile(filepath.Join(dataDir, "data.json"), []byte(dataContent), 0600)
		if err != nil {
			log.Errorf("Failed to save data.json for %s: %v", key, err)
			return err
		}
		log.Infof("Data file saved: %s", filepath.Join(dataDir, "data.json"))
	}

	return nil
}

// Extract and decodes Policies from PDP_UPDATE message using Base64Decode
func extractAndDecodePolicies(policy model.ToscaPolicy) (map[string]string, []string, error) {

	decodedPolicies := make(map[string]string)
	var keys []string
	for key, encodedPolicy := range policy.Properties.Policy {
		decodedPolicy, err := base64.StdEncoding.DecodeString(encodedPolicy)
		if err != nil {
			log.Errorf("Failed to decode policy for key: %v, %v", key, err)

			return nil, nil, err
		}

		decodedPolicies[key] = string(decodedPolicy)
		keys = append(keys, key)
		log.Tracef("Decoded policy content: %s", decodedPolicy)

		// Validate package name
		if err := validatePackageNameVar(key, string(decodedPolicy)); err != nil {

			log.Errorf("Validation for Policy: %v failed, %v", key, err)
			return nil, nil, err
		}

		log.Tracef("Decoded policy content for key '%s': %s", key, decodedPolicy)
	}

	return decodedPolicies, keys, nil
}

// Validate the package name extracted from the decoded policy against the key
func validatePackageName(key, decodedPolicyContent string) error {
	// Extract the package name from the first line of the decoded policy content
	lines := strings.Split(decodedPolicyContent, "\n")
	if len(lines) == 0 {
		return fmt.Errorf("no content found in decoded policy for key '%s'", key)
	}

	// Assume the first line contains the package declaration
	packageLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(packageLine, "package ") {
		return fmt.Errorf("package declaration not found in policy content for key '%s'", key)
	}

	// Extract the actual package name
	packageName := strings.TrimSpace(strings.TrimPrefix(packageLine, "package "))

	expectedPackageName := key

	// Compare the extracted package name with the expected package name
	if packageName != expectedPackageName {
		return fmt.Errorf("package name mismatch for key '%s': expected '%s' but got '%s'", key, expectedPackageName, packageName)
	}

	return nil
}

// Extract and decodes Data from PDP_UPDATE message using Base64Decode
func extractAndDecodeData(policy model.ToscaPolicy) (map[string]string, []string, error) {

	decodedData := make(map[string]string)
	var keys []string
	for key, encodedData := range policy.Properties.Data {
		decodedContent, err := base64.StdEncoding.DecodeString(encodedData)
		if err != nil {
			log.Errorf("Failed to decode data for key: %v, %v", key, err)
			return nil, nil, err
		}
		decodedData[key] = string(decodedContent)
		keys = append(keys, key)
		log.Tracef("Decoded data content: %s", decodedContent)
	}

	return decodedData, keys, nil
}

// Function to extract folder name based on policy
func getDirName(policy model.ToscaPolicy) []string {
	// Split the policy name to identify the folder part (i.e., the first part before ".")

	var dirNames []string

	for key, _ := range policy.Properties.Data {

		dirNames = append(dirNames, strings.ReplaceAll(consts.DataNode+key, ".", "/"))

	}
	for key, _ := range policy.Properties.Policy {

		dirNames = append(dirNames, strings.ReplaceAll(consts.Policies+"/"+key, ".", "/"))

	}

	return dirNames
}

// upsert policy to sdk.
func upsertPolicy(policy model.ToscaPolicy) error {
	decodedContent, keys, _ := extractAndDecodePoliciesVar(policy)
	for _, key := range keys {
		policyContent := decodedContent[key]
		err := opasdk.UpsertPolicyVar(context.Background(), key, []byte(policyContent))
		if err != nil {
			log.Errorf("Failed to Insert Policy %v", err)
			return err
		}
	}

	return nil
}

// handles writing data to sdk.
func upsertData(policy model.ToscaPolicy) error {
	decodedDataContent, dataKeys, _ := extractAndDecodeDataVar(policy)
	sort.Sort(utils.ByDotCount{Keys: dataKeys, Ascend: true})
	for _, dataKey := range dataKeys {
		dataContent := decodedDataContent[dataKey]
		reader := bytes.NewReader([]byte(dataContent))
		decoder := json.NewDecoder(reader)
		decoder.UseNumber()

		var wdata interface{}
		err := decoder.Decode(&wdata)
		if err != nil {
			log.Errorf("Failed to Insert Data: %s: %v", policy.Name, err)
			return err

		}
		keypath := "/" + strings.Replace(dataKey, ".", "/", -1)
		err = opasdk.WriteDataVar(context.Background(), keypath, wdata)
		if err != nil {
			log.Errorf("Failed to Write Data: %s: %v", policy.Name, err)
			return err

		}

	}
	return nil
}

// handles policy deployment
func handlePolicyDeployment(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {
	var failureMessages []string
	successPolicies := make(map[string]string)

	// Check if policy is deployed previously
	pdpUpdate.PoliciesToBeDeployed = checkIfPolicyAlreadyDeployed(pdpUpdate)

	for _, policy := range pdpUpdate.PoliciesToBeDeployed {
		// Validate the policy

		policyAllowed, err := validateParentPolicyVar(policy)
		if err != nil {
			log.Warnf("Tosca Policy Id validation failed for policy nameas it is a parent folder:%s, %v", policy.Name, err)
			failureMessages = append(failureMessages, fmt.Sprintf("%s, %v", policy.Name, err))
			metrics.IncrementDeployFailureCount()
			metrics.IncrementTotalErrorCount()
			continue
		}
		if policyAllowed {
			log.Debugf("Policy Is Allowed: %s", policy.Name)
		}

		if err := utils.ValidateToscaPolicyJsonFields(policy); err != nil {
			log.Debugf("Tosca Policy Validation Failed for policy Name: %s, %v", policy.Name, err)
			failureMessages = append(failureMessages, fmt.Sprintf("Tosca Policy Validation failed for Policy: %s: %v", policy.Name, err))
			metrics.IncrementDeployFailureCount()
			metrics.IncrementTotalErrorCount()
			continue
		}

		// Create and store policy data
		if err := createAndStorePolicyDataVar(policy); err != nil {
			failureMessages = append(failureMessages, fmt.Sprintf("%s: %v", policy.Name, err))
			metrics.IncrementDeployFailureCount()
			metrics.IncrementTotalErrorCount()
			continue
		}

		// Build the bundle
		if err := verifyPolicyByBundleCreation(policy); err != nil {
			failureMessages = append(failureMessages, fmt.Sprintf("Failed to build Rego File for %s: %v", policy.Name, err))
			metrics.IncrementDeployFailureCount()
			metrics.IncrementTotalErrorCount()
			continue
		}

		// Upsert policy and data
		if err := upsertPolicyAndData(policy, successPolicies); err != nil {
			failureMessages = append(failureMessages, err.Error())
			metrics.IncrementDeployFailureCount()
			metrics.IncrementTotalErrorCount()
			continue
		} else {
			successPolicies[policy.Name] = policy.Version
			if _, err := policymap.UpdateDeployedPoliciesinMap(policy); err != nil {
				log.Warnf("Failed to store policy data map after deploying policy %s: %v", policy.Name, err)
			}
		}
		metrics.IncrementDeploySuccessCount()
		log.Debugf("Loaded Policy: %s", policy.Name)

	}

	totalPolicies := policymap.GetTotalDeployedPoliciesCountFromMap()
	metrics.SetTotalPoliciesCount(int64(totalPolicies))

	return failureMessages, successPolicies
}

// checks if policy exists in the map.
func checkIfPolicyAlreadyDeployed(pdpUpdate model.PdpUpdate) []model.ToscaPolicy {
	if len(policymap.LastDeployedPolicies) > 0 {
		log.Debugf("Check if Policy is Already Deployed: %v", policymap.LastDeployedPolicies)
		return policymap.VerifyAndReturnPoliciesToBeDeployed(policymap.LastDeployedPolicies, pdpUpdate)
	}
	return pdpUpdate.PoliciesToBeDeployed
}

// verfies policy by creating bundle.
func verifyPolicyByBundleCreation(policy model.ToscaPolicy) error {
	// get directory name
	dirNames := []string{strings.ReplaceAll(consts.DataNode+"/"+policy.Name, ".", "/"), strings.ReplaceAll(consts.Policies+"/"+policy.Name, ".", "/")}
	// create bundle
	output, err := createBundleFuncVar(exec.Command, policy)
	if err != nil {
		log.Warnf("Failed to initialize bundle for %s: %s", policy.Name, string(output))
		for _, dirPath := range dirNames {
			if removeErr := utils.RemoveDirectory(dirPath); removeErr != nil {
				log.Errorf("Error removing directory for policy %s: %v", policy.Name, removeErr)
			}
		}
		log.Debugf("Directory cleanup as bundle creation failed")
		return fmt.Errorf("failed to build bundle: %v", err)
	}
	return nil
}

// handles Upsert func for policy and data
func upsertPolicyAndData(policy model.ToscaPolicy, successPolicies map[string]string) error {
	if err := upsertPolicyFunc(policy); err != nil {
		log.Warnf("Failed to upsert policy: %v", err)
		return fmt.Errorf("Failed to Insert Policy: %s: %v", policy.Name, err)
	}

	if err := upsertDataFunc(policy); err != nil {
		return fmt.Errorf("Failed to Write Data: %s: %v", policy.Name, err)
	}

	return nil
}

// validates whether new policy is parent of the existing policy
func validateParentPolicy(policy model.ToscaPolicy) (bool, error) {
	policiesmap, err := policymap.UnmarshalLastDeployedPolicies(policymap.LastDeployedPolicies)
	if err != nil {
		log.Warnf("Failed to extract deployed policies: %v", err)
		return false, err
	}

	policyAllowed, err := utils.IsPolicyNameAllowed(policy, policiesmap)

	if err != nil {
		log.Warnf("Tosca Policy Id validation failed for policy nameas it is a parent folder:%s, %v", policy.Name, err)
		return false, err
	}
	return policyAllowed, nil

}
