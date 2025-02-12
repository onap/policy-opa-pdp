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

// will process the update message from pap and send the pdp status response.
package handler

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/bundleserver"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpattributes"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"strings"
)

var (
	basePolicyDir = consts.Policies
	baseDataDir   = consts.Data
)

// Handles messages of type PDP_UPDATE sent from the Policy Administration Point (PAP).
// It validates the incoming data, updates PDP attributes, and sends a response back to the sender.
func pdpUpdateMessageHandler(message []byte, p publisher.PdpStatusSender) error {

	var failureMessages []string
	var pdpUpdate model.PdpUpdate
	var loggingPoliciesList string
	err := json.Unmarshal(message, &pdpUpdate)
	if err != nil {
		log.Debugf("Failed to UnMarshal Messages: %v\n", err)
		resMessage := fmt.Errorf("PDP Update Failed: %v", err)
		if err := sendFailureResponse(p, &pdpUpdate, resMessage); err != nil {
			log.Debugf("Failed to send update error response: %v", err)
			return err
		}
		return err
	}

	//Initialize Validator and validate Struct after unmarshalling
	err = utils.ValidateFieldsStructs(pdpUpdate)
	if err != nil {
		resMessage := fmt.Errorf("PDP Update Failed: %v", err)
		if err := sendFailureResponse(p, &pdpUpdate, resMessage); err != nil {
			log.Debugf("Failed to send update error response: %v", err)
			return err
		}
		return err
	}

	log.Debugf("PDP_UPDATE Message received: %s", string(message))

	pdpattributes.SetPdpSubgroup(pdpUpdate.PdpSubgroup)
	pdpattributes.SetPdpHeartbeatInterval(pdpUpdate.PdpHeartbeatIntervalMs)

	if len(pdpUpdate.PoliciesToBeDeployed) > 0 {
		failureMessage, successfullyDeployedPolicies := handlePolicyDeployment(pdpUpdate, p)
		mapJson, err := policymap.FormatMapofAnyType(successfullyDeployedPolicies)
		if len(failureMessage) > 0 {
			failureMessages = append(failureMessages, "{Deployment Errors:"+strings.Join(failureMessage, "")+"}")
		}
		if err != nil {
			failureMessages = append(failureMessages, "|Internal Map Error:"+err.Error()+"|")
			resMessage := fmt.Errorf("PDP Update Failed: failed to format successfullyDeployedPolicies json %v", failureMessages)
			if err = sendFailureResponse(p, &pdpUpdate, resMessage); err != nil {
				log.Debugf("Failed to send update error response: %v", err)
				return err
			}
		}
		loggingPoliciesList = mapJson
	}

	// Check if "PoliciesToBeUndeployed" is empty or not
	if len(pdpUpdate.PoliciesToBeUndeployed) > 0 {
		log.Infof("Found Policies to be undeployed")
		failureMessage, successfullyUndeployedPolicies := handlePolicyUndeployment(pdpUpdate, p)
		mapJson, err := policymap.FormatMapofAnyType(successfullyUndeployedPolicies)
		if len(failureMessage) > 0 {
			failureMessages = append(failureMessages, "{UnDeployment Errors:"+strings.Join(failureMessage, "")+"}")
		}
		if err != nil {
			failureMessages = append(failureMessages, "|Internal Map Error:"+err.Error()+"|")
			resMessage := fmt.Errorf("PDP Update Failed: failed to format successfullyUnDeployedPolicies json %v", failureMessages)
			if err = sendFailureResponse(p, &pdpUpdate, resMessage); err != nil {
				log.Debugf("Failed to send update error response: %v", err)
				return err
			}
		}
		loggingPoliciesList = mapJson
	}

	if len(pdpUpdate.PoliciesToBeDeployed) == 0 && len(pdpUpdate.PoliciesToBeUndeployed) == 0 {
		//Response for PAP Registration
		err = sendSuccessResponse(p, &pdpUpdate, "PDP UPDATE is successfull")
		if err != nil {
			log.Debugf("Failed to Send Update Response Message: %v\n", err)
			return err
		}
	} else {
		//Send Response for Deployment or Undeployment or when both deployment and undeployment comes together
		if err := sendPDPStatusResponse(pdpUpdate, p, loggingPoliciesList, failureMessages); err != nil {
			return err
		}
	}
	log.Infof("PDP_STATUS Message Sent Successfully")
	go publisher.StartHeartbeatIntervalTimer(pdpattributes.PdpHeartbeatInterval, p)
	return nil
}

// build bundle tar file
func createBundleFunc(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error) {
	return bundleserver.BuildBundle(execCmd)
}

func sendSuccessResponse(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, respMessage string) error {
	if err := publisher.SendPdpUpdateResponse(p, pdpUpdate, respMessage); err != nil {
		return err
	}
	return nil
}

func sendFailureResponse(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, respMessage error) error {
	if err := publisher.SendPdpUpdateErrorResponse(p, pdpUpdate, respMessage); err != nil {
		return err
	}
	return nil
}

func sendPDPStatusResponse(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender, loggingPoliciesList string, failureMessages []string) error {
	if len(failureMessages) > 0 {
		resMessage := fmt.Errorf("PDP Update Failed: %v", failureMessages)
		if err := sendFailureResponse(p, &pdpUpdate, resMessage); err != nil {
			log.Warnf("Failed to send update error response: %v", err)
			return err
		}
	} else {

		if len(pdpUpdate.PoliciesToBeUndeployed) == 0 {
			resMessage := fmt.Sprintf("PDP Update Successful for all policies: %v", loggingPoliciesList)
			if err := sendSuccessResponse(p, &pdpUpdate, resMessage); err != nil {
				log.Warnf("Failed to send update response: %v", err)
				return err
			}
			log.Infof("Processed policies_to_be_deployed successfully")
		} else if len(pdpUpdate.PoliciesToBeDeployed) == 0 {

			resMessage := fmt.Sprintf("PDP Update Policies undeployed :%v", loggingPoliciesList)

			if err := sendSuccessResponse(p, &pdpUpdate, resMessage); err != nil {
				log.Warnf("Failed to Send Update Response Message: %v", err)
				return err
			}
			log.Infof("Processed policies_to_be_undeployed successfully")
		} else {

			if err := sendSuccessResponse(p, &pdpUpdate, "PDP UPDATE is successfull"); err != nil {
				log.Warnf("Failed to Send Update Response Message: %v", err)
				return err
			}
		}

	}
	return nil
}
