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
	"fmt"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"strings"
)

// processPoliciesTobeUndeployed handles the undeployment of policies
func processPoliciesTobeUndeployed(undeployedPolicies map[string]string) ([]string, map[string]string) {
	var failureMessages []string

	successfullyUndeployedPolicies := make(map[string]string)

	// Unmarshal the last known policies
	deployedPolicies, err := policymap.UnmarshalLastDeployedPolicies(policymap.LastDeployedPolicies)
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies: %v", err)
	}

	for policyID, policyVersion := range undeployedPolicies {
		// Check if undeployed policy exists in deployedPolicies
		matchedPolicy := findDeployedPolicy(policyID, policyVersion, deployedPolicies)
		if matchedPolicy != nil {
			// Handle undeployment for the policy
			errs := policyUndeploymentAction(matchedPolicy)
			if len(errs) > 0 {
				metrics.IncrementUndeployFailureCount()
				metrics.IncrementTotalErrorCount()
				failureMessages = append(failureMessages, errs...)
			}
			deployedPoliciesMap, err := policymap.RemoveUndeployedPoliciesfromMap(matchedPolicy)
			if err != nil {
				log.Warnf("Policy Name: %s, Version: %s is not removed from LastDeployedPolicies", policyID, policyVersion)
				failureMessages = append(failureMessages, "Error in removing from LastDeployedPolicies")
			}
			log.Debugf("Policies Map After Undeployment : %s", deployedPoliciesMap)
			metrics.IncrementUndeploySuccessCount()
			successfullyUndeployedPolicies[policyID] = policyVersion
		} else {
			// Log failure if no match is found
			log.Debugf("Policy Name: %s, Version: %s is marked for undeployment but was not deployed", policyID, policyVersion)
			continue
		}
	}

        totalPolicies := policymap.GetTotalDeployedPoliciesCountFromMap()
        metrics.SetTotalPoliciesCount(int64(totalPolicies))

	return failureMessages, successfullyUndeployedPolicies
}

func handlePolicyUndeployment(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {

	// Extract undeployed policies into a dictionary
	undeployedPoliciesDict := extractUndeployedPolicies(pdpUpdate.PoliciesToBeUndeployed)

	// Process undeployment actions
	errorMessages, successfullyUndeployedPolicies := processPoliciesTobeUndeployed(undeployedPoliciesDict)

	return errorMessages, successfullyUndeployedPolicies

}

// ExtractUndeployedPolicies extracts policy names and versions into a map
func extractUndeployedPolicies(policies []model.ToscaConceptIdentifier) map[string]string {
	undeployedPoliciesDict := make(map[string]string)
	for _, policy := range policies {
		undeployedPoliciesDict[policy.Name] = policy.Version
		log.Infof("Extracted Policy Name: %s, Version: %s for undeployment", policy.Name, policy.Version)
	}
	return undeployedPoliciesDict
}

// HandlePolicyUndeployment processes the actual undeployment actions for a policy
func policyUndeploymentAction(policy map[string]interface{}) []string {
	var failureMessages []string

	// Delete "policy" sdk and directories
	policyErrors := removePolicyFromSdkandDir(policy)
	failureMessages = append(failureMessages, policyErrors...)

	// Delete "data" sdk and directories
	dataErrors := removeDataFromSdkandDir(policy)
	failureMessages = append(failureMessages, dataErrors...)

	return failureMessages
}

// removeDataFromSdkandDir handles the "data" directories in the policy
func removeDataFromSdkandDir(policy map[string]interface{}) []string {
	var failureMessages []string

	if dataKeys, ok := policy["data"].([]interface{}); ok {
		for _, dataKey := range dataKeys {
			keyPath := "/" + strings.Replace(dataKey.(string), ".", "/", -1)
			log.Debugf("Deleting data from OPA at keypath: %s", keyPath)
			if err := opasdk.DeleteData(context.Background(), keyPath); err != nil {
				failureMessages = append(failureMessages, err.Error())
				continue
			}
			if err := removeDataDirectory(keyPath); err != nil {
				failureMessages = append(failureMessages, err.Error())
			}
		}
	} else {
		failureMessages = append(failureMessages, fmt.Sprintf("%s:%s Invalid JSON structure: 'data' is missing or not an array", policy["policy-id"], policy["policy-version"]))
	}

	return failureMessages
}

// removePolicyFromSdkandDir handles the "policy" directories in the policy
func removePolicyFromSdkandDir(policy map[string]interface{}) []string {
	var failureMessages []string

	if policyKeys, ok := policy["policy"].([]interface{}); ok {
		for _, policyKey := range policyKeys {
			keyPath := "/" + strings.Replace(policyKey.(string), ".", "/", -1)
			if err := opasdk.DeletePolicy(context.Background(), policyKey.(string)); err != nil {
				failureMessages = append(failureMessages, err.Error())
				continue
			}
			if err := removePolicyDirectory(keyPath); err != nil {
				failureMessages = append(failureMessages, err.Error())
			}
		}
	} else {
		failureMessages = append(failureMessages, fmt.Sprintf("%s:%s Invalid JSON structure: 'policy' is missing or not an array", policy["policy-id"], policy["policy-version"]))
	}

	return failureMessages
}

// RemoveDataDirectory removes a directory for data
func removeDataDirectory(dataKey string) error {
	dataPath := filepath.Join(consts.Data, dataKey)
	log.Debugf("Removing data directory: %s", dataPath)
	if err := utils.RemoveDirectory(dataPath); err != nil {
		return fmt.Errorf("Failed to handle directory for data %s: %v", dataPath, err)
	}
	return nil
}

// RemovePolicyDirectory removes a directory for policies
func removePolicyDirectory(policyKey string) error {
	policyPath := filepath.Join(consts.Policies, policyKey)
	log.Debugf("Removing policy directory: %s", policyPath)
	if err := utils.RemoveDirectory(policyPath); err != nil {
		return fmt.Errorf("Failed to handle directory for policy %s: %v", policyPath, err)
	}
	return nil
}

// findDeployedPolicy searches for a policy in deployedPolicies
func findDeployedPolicy(policyID, policyVersion string, deployedPolicies []map[string]interface{}) map[string]interface{} {
	for _, policy := range deployedPolicies {
		// Extract policy-id and policy-version from the deployed policy
		id, idOk := policy["policy-id"].(string)
		version, versionOk := policy["policy-version"].(string)

		// Check if the deployed policy matches the undeployed policy
		if idOk && versionOk && id == policyID && version == policyVersion {
			return policy
		}
	}
	return nil
}
