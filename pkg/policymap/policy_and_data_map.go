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
package policymap

import (
	"encoding/json"
	"fmt"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"sync"
)

type (
	FormatMapOfAnyTypeFunc[T any] func(mapOfAnyType T) (string, error)
)

var (
	// lastDeployedPolicies is written by the Kafka handler goroutine while the decision
	// and data HTTP handlers, the status publisher and the heartbeat all read it, so
	// every access goes through mu. Read-modify-write callers hold the write lock for
	// the whole sequence: taking it only around the store would let two concurrent
	// updates each drop the other's policy.
	mu                   sync.RWMutex
	lastDeployedPolicies string

	FormatMapOfAnyTypeVar FormatMapOfAnyTypeFunc[interface{}] = FormatMapofAnyType
)

// GetLastDeployedPolicies returns the JSON document describing what is currently deployed.
func GetLastDeployedPolicies() string {
	mu.RLock()
	defer mu.RUnlock()
	return lastDeployedPolicies
}

// SetLastDeployedPolicies replaces the deployed policies document.
func SetLastDeployedPolicies(policiesMap string) {
	mu.Lock()
	defer mu.Unlock()
	lastDeployedPolicies = policiesMap
}

func formatPolicyAndDataMap(deployedPolicies []map[string]interface{}) (string, error) {

	// Create the final JSON
	finalMap := map[string]interface{}{
		"deployed_policies_dict": deployedPolicies,
	}

	// Marshal the final map into JSON
	policyDataJSON, err := FormatMapOfAnyTypeVar(finalMap)
	if err != nil {
		return "", fmt.Errorf("failed to format json: %v", err)
	}

	return policyDataJSON, nil
}

// storeDeployedPoliciesLocked renders deployedPolicies and publishes the result.
// mu must already be held for writing.
func storeDeployedPoliciesLocked(deployedPolicies []map[string]interface{}) (string, error) {
	policyDataJSON, err := formatPolicyAndDataMap(deployedPolicies)
	if err != nil {
		return lastDeployedPolicies, err
	}

	lastDeployedPolicies = policyDataJSON
	log.Infof("PoliciesDeployed Map: %v", lastDeployedPolicies)

	return lastDeployedPolicies, nil
}

func FormatMapofAnyType[T any](mapOfAnyType T) (string, error) {
	// Marshal the final map into JSON
	jsonBytes, err := json.MarshalIndent(mapOfAnyType, "", " ")
	if err != nil {
		return "", fmt.Errorf("failed to format json: %v", err)
	}

	return string(jsonBytes), nil
}

func UnmarshalLastDeployedPolicies(lastdeployedPolicies string) ([]map[string]interface{}, error) {
	if len(lastdeployedPolicies) == 0 {
		return []map[string]interface{}{}, nil
	}

	var policiesMap struct {
		DeployedPoliciesDict []map[string]interface{} `json:"deployed_policies_dict"`
	}

	err := json.Unmarshal([]byte(lastdeployedPolicies), &policiesMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LastDeployedPolicies: %v", err)
	}

	return policiesMap.DeployedPoliciesDict, nil
}

func UpdateDeployedPoliciesinMap(policy model.ToscaPolicy) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	// Unmarshal the last known policies
	deployedPolicies, err := UnmarshalLastDeployedPolicies(lastDeployedPolicies)
	if err != nil {
		log.Warnf("Aborting update; LastDeployedPolicies is corrupt: %v", err)
		return lastDeployedPolicies, err
	}

	dataKeys := make([]string, 0, len(policy.Properties.Data))
	policyKeys := make([]string, 0, len(policy.Properties.Policy))

	for key := range policy.Properties.Data {
		dataKeys = append(dataKeys, key)
	}

	for key := range policy.Properties.Policy {
		policyKeys = append(policyKeys, key)
	}

	directoryMap := map[string]interface{}{
		consts.PolicyId:      policy.Metadata.PolicyID,
		consts.PolicyVersion: policy.Metadata.PolicyVersion,
		"data":               dataKeys,
		"policy":             policyKeys,
	}
	deployedPolicies = append(deployedPolicies, directoryMap)
	return storeDeployedPoliciesLocked(deployedPolicies)
}

func RemoveUndeployedPoliciesfromMap(undeployedPolicy map[string]interface{}) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	// Unmarshal the last known policies
	deployedPolicies, err := UnmarshalLastDeployedPolicies(lastDeployedPolicies)
	if err != nil {
		log.Warnf("Aborting update; LastDeployedPolicies is corrupt: %v", err)
		return lastDeployedPolicies, err
	}

	remainingPolicies := []map[string]interface{}{}

	for _, policy := range deployedPolicies {
		shouldRetain := true
		if policy[consts.PolicyId] == undeployedPolicy[consts.PolicyId] && policy[consts.PolicyVersion] == undeployedPolicy[consts.PolicyVersion] {
			shouldRetain = false
		}
		if shouldRetain {
			remainingPolicies = append(remainingPolicies, policy)
		}
	}

	return storeDeployedPoliciesLocked(remainingPolicies)
}

func VerifyAndReturnPoliciesToBeDeployed(lastdeployedPoliciesMap string, pdpUpdate model.PdpUpdate) []model.ToscaPolicy {
	type PoliciesMap struct {
		DeployedPoliciesDict []map[string]interface{} `json:"deployed_policies_dict"`
	}

	var policiesMap PoliciesMap
	err := json.Unmarshal([]byte(lastdeployedPoliciesMap), &policiesMap)
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies While Verifying Policies to be deployed: %v", err)
		return pdpUpdate.PoliciesToBeDeployed
	}

	deployedPolicies := policiesMap.DeployedPoliciesDict
	var policiesToBeDeployed []model.ToscaPolicy

	for _, deployingPolicy := range pdpUpdate.PoliciesToBeDeployed {
		shouldDeploy := true
		for _, deployedPolicy := range deployedPolicies {
			if deployedPolicy[consts.PolicyId] == deployingPolicy.Name && deployedPolicy[consts.PolicyVersion] == deployingPolicy.Version {
				log.Infof("Policy Previously deployed: %v %v, skipping", deployingPolicy.Name, deployingPolicy.Version)
				shouldDeploy = false
				break
			}
		}

		if shouldDeploy {
			log.Infof("Policy is new and should be deployed: %v %v", deployingPolicy.Name, deployingPolicy.Version)
			policiesToBeDeployed = append(policiesToBeDeployed, deployingPolicy)
		}
	}

	return policiesToBeDeployed

}

func ExtractDeployedPolicies(policiesMap string) []model.ToscaConceptIdentifier {

	// Unmarshal the last known policies
	deployedPolicies, err := UnmarshalLastDeployedPolicies(policiesMap)
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies While Extracting Deployed Policies: %v", err)
	}

	pdpstatus := model.PdpStatus{
		Policies: []model.ToscaConceptIdentifier{},
	}

	for _, policy := range deployedPolicies {

		// Extract policy-id and policy-version
		policyID, idOk := policy[consts.PolicyId].(string)
		policyVersion, versionOk := policy[consts.PolicyVersion].(string)
		if !idOk || !versionOk {
			log.Warnf("Skipping deployed policy with missing/invalid policy-id or policy-version")
			continue
		}
		tosca := model.ToscaConceptIdentifier{
			Name:    policyID,
			Version: policyVersion,
		}
		pdpstatus.Policies = append(pdpstatus.Policies, tosca)
	}
	return pdpstatus.Policies
}

func CheckIfPolicyAlreadyExists(policyId string) bool {
	policiesMap := GetLastDeployedPolicies()
	if len(policiesMap) > 0 {
		// Unmarshal the last known policies
		deployedPolicies, err := UnmarshalLastDeployedPolicies(policiesMap)
		if err != nil {
			log.Warnf("Failed to unmarshal LastDeployedPolicies While Checking if Policy Already Exists: %v", err)
		}

		log.Debugf("deployedPolicies %s", deployedPolicies)

		for _, policy := range deployedPolicies {
			if policy[consts.PolicyId] == policyId {
				return true
			}
		}
	}
	return false
}

func GetTotalDeployedPoliciesCountFromMap() int {
	deployedPolicies, err := UnmarshalLastDeployedPolicies(GetLastDeployedPolicies())
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies While Getting TotalDeployedPoliciesCountFromMap: %v", err)
		return 0
	}
	return len(deployedPolicies)
}
