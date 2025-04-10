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
	"fmt"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"sort"
	"strings"
)

type (
	HandlePolicyUndeploymentFunc        func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string)
	opasdkGetDataFunc                   func(ctx context.Context, dataPath string) (data *oapicodegen.OPADataResponse_Data, err error)
	policyUndeploymentActionFunc        func(policy map[string]interface{}) []string
	removeUndeployedPoliciesfromMapFunc func(undeployedPolicy map[string]interface{}) (string, error)
)

var (
	handlePolicyUndeploymentVar HandlePolicyUndeploymentFunc = handlePolicyUndeployment

	removeDirectoryFunc = utils.RemoveDirectory

	deleteDataSdkFunc = opasdk.DeleteData

	deletePolicySdkFunc = opasdk.DeletePolicy

	opasdkGetData opasdkGetDataFunc = opasdk.GetDataInfo

	removeDataDirectoryFunc = removeDataDirectory

	removePolicyDirectoryFunc = removePolicyDirectory

	policyUndeploymentActionVar policyUndeploymentActionFunc = policyUndeploymentAction

	removeUndeployedPoliciesfromMapVar removeUndeployedPoliciesfromMapFunc = policymap.RemoveUndeployedPoliciesfromMap

	removePolicyFromSdkandDirFunc = removePolicyFromSdkandDir

	removeDataFromSdkandDirFunc = removeDataFromSdkandDir

	analyseEmptyParentNodesFunc = analyseEmptyParentNodes

	processDataDeletionFromSdkAndDirFunc = processDataDeletionFromSdkAndDir
)

// processPoliciesTobeUndeployed handles the undeployment of policies
func processPoliciesTobeUndeployed(undeployedPolicies map[string]string) ([]string, map[string]string) {
	var failureMessages []string
	hasFailure := false

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
			errs := policyUndeploymentActionVar(matchedPolicy)
			if len(errs) > 0 {
				hasFailure = true
				metrics.IncrementUndeployFailureCount()
				metrics.IncrementTotalErrorCount()
				failureMessages = append(failureMessages, errs...)
			}
			deployedPoliciesMap, err := removeUndeployedPoliciesfromMapVar(matchedPolicy)
			if err != nil {
				log.Warnf("Policy Name: %s, Version: %s is not removed from LastDeployedPolicies", policyID, policyVersion)
				failureMessages = append(failureMessages, "Error in removing from LastDeployedPolicies")
			}
			log.Debugf("Policies Map After Undeployment : %s", deployedPoliciesMap)
			if !hasFailure {
				metrics.IncrementUndeploySuccessCount()
				successfullyUndeployedPolicies[policyID] = policyVersion
			}
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
	policyErrors := removePolicyFromSdkandDirFunc(policy)
	failureMessages = append(failureMessages, policyErrors...)

	// Delete "data" sdk and directories
	dataErrors := removeDataFromSdkandDirFunc(policy)
	failureMessages = append(failureMessages, dataErrors...)

	return failureMessages
}

// removeDataFromSdkandDir handles the "data" directories in the policy
func removeDataFromSdkandDir(policy map[string]interface{}) []string {
	var failureMessages []string

	if dataKeys, ok := policy["data"].([]interface{}); ok {
		var dataKeysSlice []string
		for _, dataKey := range dataKeys {
			if strKey, ok := dataKey.(string); ok {
				dataKeysSlice = append(dataKeysSlice, strKey)
			} else {
				failureMessages = append(failureMessages, fmt.Sprintf("Invalid Key :%v", dataKey))
			}
		}
		sort.Sort(utils.ByDotCount{Keys: dataKeysSlice, Ascend: false})

		for _, keyPath := range dataKeysSlice {
			keyPath = "/" + strings.Replace(keyPath, ".", "/", -1)
			log.Debugf("Deleting data from OPA : %s", keyPath)
			errs := processDataDeletionFromSdkAndDirFunc(keyPath)
			failureMessages = append(failureMessages, errs...)
		}
	} else {
		policyID, _ := policy[consts.PolicyId].(string)
		policyVersion, _ := policy[consts.PolicyVersion].(string)
		failureMessages = append(failureMessages, fmt.Sprintf("%v:%v Invalid JSON structure: 'data' is missing or not an array", policyID, policyVersion))
	}

	return failureMessages
}

func processDataDeletionFromSdkAndDir(keyPath string) []string {
	var failureMessages []string
	var dataPath string
	var err error
	// Fetch data first
	// Call the function to check and Analyse empty parent nodes
	if dataPath, err = analyseEmptyParentNodesFunc(keyPath); err != nil {
		failureMessages = append(failureMessages, err.Error())
	}
	if err := deleteDataSdkFunc(context.Background(), dataPath); err != nil {
		log.Errorf("Error while deleting Data from SDK for path : %s , %v", keyPath, err.Error())
		failureMessages = append(failureMessages, err.Error())
	}
	if err := removeDataDirectoryFunc(keyPath); err != nil {
		failureMessages = append(failureMessages, err.Error())
	}

	return failureMessages

}

// removePolicyFromSdkandDir handles the "policy" directories in the policy
func removePolicyFromSdkandDir(policy map[string]interface{}) []string {
	var failureMessages []string

	if policyKeys, ok := policy["policy"].([]interface{}); ok {
		for _, policyKey := range policyKeys {
			keyPath := "/" + strings.Replace(policyKey.(string), ".", "/", -1)
			log.Debugf("Deleting Policy from OPA : %s", keyPath)
			if err := deletePolicySdkFunc(context.Background(), policyKey.(string)); err != nil {
				failureMessages = append(failureMessages, err.Error())
				continue
			}
			if err := removePolicyDirectoryFunc(keyPath); err != nil {
				failureMessages = append(failureMessages, err.Error())
			}
		}
	} else {
		failureMessages = append(failureMessages, fmt.Sprintf("%s:%s Invalid JSON structure: 'policy' is missing or not an array", policy[consts.PolicyId], policy[consts.PolicyVersion]))
	}

	return failureMessages
}

// RemoveDataDirectory removes a directory for data
func removeDataDirectory(dataKey string) error {
	dataPath := filepath.Join(consts.Data, dataKey)
	log.Debugf("Removing data directory: %s", dataPath)
	if err := removeDirectoryFunc(dataPath); err != nil {
		return fmt.Errorf("Failed to handle directory for data %s: %v", dataPath, err)
	}
	return nil
}

// RemovePolicyDirectory removes a directory for policies
func removePolicyDirectory(policyKey string) error {
	policyPath := filepath.Join(consts.Policies, policyKey)
	log.Debugf("Removing policy directory: %s", policyPath)
	if err := removeDirectoryFunc(policyPath); err != nil {
		return fmt.Errorf("Failed to handle directory for policy %s: %v", policyPath, err)
	}
	return nil
}

// findDeployedPolicy searches for a policy in deployedPolicies
func findDeployedPolicy(policyID, policyVersion string, deployedPolicies []map[string]interface{}) map[string]interface{} {
	for _, policy := range deployedPolicies {
		// Extract policy-id and policy-version from the deployed policy
		id, idOk := policy[consts.PolicyId].(string)
		version, versionOk := policy[consts.PolicyVersion].(string)

		// Check if the deployed policy matches the undeployed policy
		if idOk && versionOk && id == policyID && version == policyVersion {
			return policy
		}
	}
	return nil
}

// analyzeEmptyParentNodes constructs the parent path based on the provided dataPath.
// It checks if any parent nodes become empty after the deletion of the last child key.
//
// This function takes a JSON representation of parent data and a data path,
// splits the path into segments, and determines the eligible paths for deletion.
//
// If a parent node has only one child and that child is to be deleted,
// the full path up to that parent will be returned. If no eligible parents
// are found by the time it reaches back to the root, the original path will be returned.
func analyseEmptyParentNodes(dataPath string) (string, error) {
	log.Debugf("Analyzing dataPath: %s", dataPath)
	// Split the dataPath into segments
	pathSegments := strings.Split(dataPath, "/")
	log.Debugf("Path segments: %+v", pathSegments)
	// If the path does not have at least 3 segments, treat it as a leaf node
	if len(pathSegments) < consts.SingleHierarchy {
		log.Debugf("Path doesn't have any parent-child hierarchy;so returning the original path: %s", dataPath)
		return dataPath, nil // It's a leaf node or too short; return the original path
	}
	// Prepare the parent path which is derived from the second segment
	parentKeyPath := "/" + pathSegments[1] // Assuming the immediate parent node
	log.Debugf("Detected parent path: %s", parentKeyPath)
	// Fetch the data for the detected parent path
	parentData, err := opasdkGetData(context.Background(), parentKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to get data for parent path %s: %w", parentKeyPath, err)
	}
	// Unmarshal parent data JSON into a map for analysis
	parentDataJson, err := json.Marshal(parentData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal parent data: %w", err)
	}
	// Call the method to analyze the hierarchy
	return analyzeHierarchy(parentDataJson, dataPath)
}

// analyzeHierarchy examines the provided data path against the JSON structure to determine
// the last eligible path for deletion based on parent-child relationships.
//
// The function takes a JSON object in raw format and splits the data path into segments.
// Starting from the last key, it checks each parent key to see if it has only one child.
// If so, it marks the path up to that parent as the last eligible path for deletion.
func analyzeHierarchy(parentDataJson json.RawMessage, dataPath string) (string, error) {
	// Create a map to hold the parent data
	parentMap := make(map[string]interface{})

	// Unmarshal the fetched JSON data into the parentMap
	if err := json.Unmarshal(parentDataJson, &parentMap); err != nil {
		return "", fmt.Errorf("error unmarshalling parent data: %w", err)
	}

	// Count keys in the JSON structure
	countMap := countChildKeysFromJSON(parentMap)
	// Split keys and omit the first empty element
	keys := strings.Split(dataPath, "/")[1:]
	// Default to the input path
	lastEligible := dataPath
	// Traverse the path from the last key to the first key
	// Start from the last segment and stop at the first parent
	for indexfromKeyPath := len(keys) - 1; indexfromKeyPath >= 1; indexfromKeyPath-- {
		// Identify the parent of the current path
		currentPath := strings.Join(keys[:indexfromKeyPath], "/")
		// Checking counts of the parent key
		childCount := countMap[currentPath]
		if childCount == 1 {
			// If parent has only 1 child after deletion, it is eligible
			lastEligible = "/" + currentPath // Store the path up to this parent
		} else {
			break
		}
	}

	log.Debugf("lastEligible Path: %+v", lastEligible)
	return lastEligible, nil

}

// countChildKeysFromJSON counts the number of child keys for each key in a JSON structure represented as a map.
//
// This function traverses the provided JSON map iteratively using a stack, counting
// the number of direct children for each key. The counts are stored in a map where
// the keys represent the paths in the JSON hierarchy (using slash notation) and the
// values indicate how many children each key has.
// Example Inputs and Outputs:
//
//	Given the following JSON:
//	{
//	    "node": {
//	        "collab": {
//	            "action": {
//	                "conflict": {},
//	                "others": {}
//	            },
//	            "role": {}
//	        },
//	        "role": {
//	            "role_grants": {
//	                "billing": {},
//	                "shipping": {}
//	            }
//	        }
//	    }
//	}
//	Example Output:
//	{
//	    "node": 2,
//	    "node/collab": 2,
//	    "node/collab/action": 2,
//	    "node/collab/role": 0,
//	    "node/role": 1,
//	    "node/role/role_grants": 2,
//	    "node/role/role_grants/billing": 0,
//	    "node/role/role_grants/shipping": 0
//	}
func countChildKeysFromJSON(data map[string]interface{}) map[string]int {
	countMap := make(map[string]int)

	// Creating a stack for iterative traversal with paths
	stack := []struct {
		current map[string]interface{}
		path    string
	}{
		{data, "node"}, // Start with the root node path
	}

	for len(stack) > 0 {
		// Pop the current map from the stack
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for key, value := range top.current {
			//take the full path
			currentPath := top.path + "/" + key
			if childMap, ok := value.(map[string]interface{}); ok {
				// Count the number of children for each key
				countMap[currentPath] = len(childMap)
				stack = append(stack, struct {
					current map[string]interface{}
					path    string
				}{childMap, currentPath}) // Push children map into stack with full path
			}
		}
	}
	return countMap
}
