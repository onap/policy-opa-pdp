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

// will process the update message from pap and send the pdp status response.
package policymap

import (
	"encoding/json"
	"fmt"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
)

var (
	LastDeployedPolicies string
)

func formatPolicyAndDataMap(deployedPolicies []map[string]interface{}) (string, error) {

	// Create the final JSON
	finalMap := map[string]interface{}{
		"deployed_policies_dict": deployedPolicies,
	}

	// Marshal the final map into JSON
	policyDataJSON, err := FormatMapofAnyType(finalMap)
	if err != nil {
		return "", fmt.Errorf("failed to format json: %v", err)
	}

	// Update global state
	LastDeployedPolicies = policyDataJSON
	log.Infof("PoliciesDeployed Map: %v", LastDeployedPolicies)

	return LastDeployedPolicies, nil
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

	// Unmarshal the last known policies
	deployedPolicies, err := UnmarshalLastDeployedPolicies(LastDeployedPolicies)
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies: %v", err)
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
		"policy-id":      policy.Metadata.PolicyID,
		"policy-version": policy.Metadata.PolicyVersion,
		"data":           dataKeys,
		"policy":         policyKeys,
	}
	deployedPolicies = append(deployedPolicies, directoryMap)
	return formatPolicyAndDataMap(deployedPolicies)
}

func RemoveUndeployedPoliciesfromMap(undeployedPolicy map[string]interface{}) (string, error) {

	// Unmarshal the last known policies
	deployedPolicies, err := UnmarshalLastDeployedPolicies(LastDeployedPolicies)
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies: %v", err)
	}

	remainingPolicies := []map[string]interface{}{}

	for _, policy := range deployedPolicies {
		shouldRetain := true
		if policy["policy-id"] == undeployedPolicy["policy-id"] && policy["policy-version"] == undeployedPolicy["policy-version"] {
			shouldRetain = false
		}
		if shouldRetain {
			remainingPolicies = append(remainingPolicies, policy)
		}
	}

	return formatPolicyAndDataMap(remainingPolicies)
}

func VerifyAndReturnPoliciesToBeDeployed(lastdeployedPoliciesMap string, pdpUpdate model.PdpUpdate) []model.ToscaPolicy {
	type PoliciesMap struct {
		DeployedPoliciesDict []map[string]interface{} `json:"deployed_policies_dict"`
	}

	var policiesMap PoliciesMap
	err := json.Unmarshal([]byte(lastdeployedPoliciesMap), &policiesMap)
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies: %v", err)
		return pdpUpdate.PoliciesToBeDeployed
	}

	deployedPolicies := policiesMap.DeployedPoliciesDict
	var policiesToBeDeployed []model.ToscaPolicy

	for _, deployingPolicy := range pdpUpdate.PoliciesToBeDeployed {
		shouldDeploy := true
		for _, deployedPolicy := range deployedPolicies {
			if deployedPolicy["policy-id"] == deployingPolicy.Name && deployedPolicy["policy-version"] == deployingPolicy.Version {
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
		log.Warnf("Failed to unmarshal LastDeployedPolicies: %v", err)
	}

	pdpstatus := model.PdpStatus{
		Policies: []model.ToscaConceptIdentifier{},
	}

	for _, policy := range deployedPolicies {

		// Extract policy-id and policy-version
		policyID, idOk := policy["policy-id"].(string)
		policyVersion, versionOk := policy["policy-version"].(string)
		if !idOk || !versionOk {
			log.Warnf("Missing or invalid policy-id or policy-version")
			return nil
		}
		tosca := model.ToscaConceptIdentifier{
			Name:    policyID,
			Version: policyVersion,
		}
		pdpstatus.Policies = append(pdpstatus.Policies, tosca)
	}
	return pdpstatus.Policies
}

func GetTotalDeployedPoliciesCountFromMap() int {
        deployedPolicies, err := UnmarshalLastDeployedPolicies(LastDeployedPolicies)
        if err != nil {
                log.Warnf("Failed to unmarshal LastDeployedPolicies: %v", err)
		return 0
        }
        return len(deployedPolicies)
}
