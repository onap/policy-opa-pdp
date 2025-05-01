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
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpattributes"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"strings"
)

type (
	sendSuccessResponseFunc         func(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, respMessage string) error
	sendFailureResponseFunc         func(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, respMessage error) error
	createBundleFuncRef             func(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error)
	handlePdpUpdateDeploymentFunc   func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string)
	handlePdpUpdateUndeploymentFunc func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string)
	sendFinalResponseFunc           func(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, loggingPoliciesList string, failureMessages []string) error
)

var (
	basePolicyDir                                                  = consts.Policies
	baseDataDir                                                    = consts.Data
	sendSuccessResponseVar         sendSuccessResponseFunc         = sendSuccessResponse
	sendFailureResponseVar         sendFailureResponseFunc         = sendFailureResponse
	sendFinalResponseVar           sendFinalResponseFunc           = sendFinalResponse
	createBundleFuncVar            createBundleFuncRef             = createBundleFunc
	handlePdpUpdateDeploymentVar   handlePdpUpdateDeploymentFunc   = handlePdpUpdateDeployment
	handlePdpUpdateUndeploymentVar handlePdpUpdateUndeploymentFunc = handlePdpUpdateUndeployment
	sendPDPStatusResponseFunc                                      = sendPDPStatusResponse
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
		resMessage := fmt.Errorf("PDP Update Failed as failed Unmarshalling: %v", err)
		if err := sendFailureResponseVar(p, &pdpUpdate, resMessage); err != nil {
			log.Debugf("Failed to send update unmarshal error response: %v", err)
			return err
		}
		return err
	}

	//Initialize Validator and validate Struct after unmarshalling
	err = utils.ValidateFieldsStructsVar(pdpUpdate)
	if err != nil {
		resMessage := fmt.Errorf("PDP Update Failed: %v", err)
		if err := sendFailureResponseVar(p, &pdpUpdate, resMessage); err != nil {
			log.Debugf("Failed to send pdp update validate fields error response: %v", err)
			return err
		}
		return err
	}

	log.Debugf("PDP_UPDATE Message received: %s", string(message))

	pdpattributes.SetPdpSubgroup(pdpUpdate.PdpSubgroup)
	pdpattributes.SetPdpHeartbeatInterval(pdpUpdate.PdpHeartbeatIntervalMs)

	depPoliciesList, err, depFailures := handlePdpUpdateDeploymentVar(pdpUpdate, p)
	undepPoliciesList, undepErr, undepFailures := handlePdpUpdateUndeploymentVar(pdpUpdate, p)

	if err != nil {
		return err
	}

	if undepErr != nil {
		return undepErr
	}
	failureMessages = append(depFailures, undepFailures...)

	loggingPoliciesList = depPoliciesList

	if undepPoliciesList != "" {
		loggingPoliciesList += "," + undepPoliciesList
	}

	err = sendFinalResponseVar(p, &pdpUpdate, loggingPoliciesList, failureMessages)
	if err != nil {
		return err
	}

	log.Infof("PDP_STATUS Message Sent Successfully")
	log.Debug(pdpUpdate.PdpHeartbeatIntervalMs)

	if pdpattributes.PdpHeartbeatInterval != pdpUpdate.PdpHeartbeatIntervalMs && pdpUpdate.PdpHeartbeatIntervalMs != 0 {
		//restart the ticker.
		publisher.StopTicker()
		pdpattributes.SetPdpHeartbeatInterval(pdpUpdate.PdpHeartbeatIntervalMs)
		go publisher.StartHeartbeatIntervalTimer(pdpattributes.PdpHeartbeatInterval, p)
	}
	go publisher.StartHeartbeatIntervalTimer(pdpattributes.PdpHeartbeatInterval, p)
	return nil

}

func handlePdpUpdateDeployment(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string) {
	var failureMessages []string
	var mapJson string
	var err error
	if len(pdpUpdate.PoliciesToBeDeployed) > 0 {
		failureMessage, successfullyDeployedPolicies := handlePolicyDeploymentVar(pdpUpdate, p)
		mapJson, err = policymap.FormatMapOfAnyTypeVar(successfullyDeployedPolicies)
		if len(failureMessage) > 0 {
			failureMessages = append(failureMessages, "{Deployment Errors:"+strings.Join(failureMessage, "")+"}")
		}
		if err != nil {
			failureMessages = append(failureMessages, "|Internal Map Error:"+err.Error()+"|")
			resMessage := fmt.Errorf("PDP Update Failed as failed to format successfullyDeployedPolicies json %v", failureMessages)
			if err = sendFailureResponseVar(p, &pdpUpdate, resMessage); err != nil {
				log.Debugf("Failed to send update internal map  error response: %v", err)
				return "", err, failureMessages
			}
		}

	}

	return mapJson, nil, failureMessages
}

func handlePdpUpdateUndeployment(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string) {
	var failureMessages []string
	var mapJson string
	var err error

	// Check if "PoliciesToBeUndeployed" is empty or not
	if len(pdpUpdate.PoliciesToBeUndeployed) > 0 {
		log.Infof("Found Policies to be undeployed")
		failureMessage, successfullyUndeployedPolicies := handlePolicyUndeploymentVar(pdpUpdate, p)
		mapJson, err = policymap.FormatMapOfAnyTypeVar(successfullyUndeployedPolicies)
		if len(failureMessage) > 0 {
			failureMessages = append(failureMessages, "{UnDeployment Errors:"+strings.Join(failureMessage, "")+"}")
		}
		if err != nil {
			failureMessages = append(failureMessages, "|Internal Map Error:"+err.Error()+"|")
			resMessage := fmt.Errorf("PDP Update Failed as failed to format successfullyUnDeployedPolicies json %v", failureMessages)
			if err = sendFailureResponseVar(p, &pdpUpdate, resMessage); err != nil {
				log.Debugf("Failed to send update error response: %v", err)
				return "", err, failureMessages
			}
		}
	}
	return mapJson, nil, failureMessages
}

func sendFinalResponse(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, loggingPoliciesList string, failureMessages []string) error {
	if len(pdpUpdate.PoliciesToBeDeployed) == 0 && len(pdpUpdate.PoliciesToBeUndeployed) == 0 {
		//Response for PAP Registration
		return sendSuccessResponseVar(p, pdpUpdate, "PDP UPDATE is successfull")
	}
	//Send Response for Deployment or Undeployment or when both deployment and undeployment comes together
	if err := sendPDPStatusResponseFunc(*pdpUpdate, p, loggingPoliciesList, failureMessages); err != nil {
		return err
	}
	return nil
}

// build bundle tar file
func createBundleFunc(execCmd func(string, ...string) *exec.Cmd, toscaPolicy model.ToscaPolicy) (string, error) {
	return utils.BuildBundle(execCmd)
}

func sendSuccessResponse(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, respMessage string) error {
	if err := publisher.SendPdpUpdateResponseVar(p, pdpUpdate, respMessage); err != nil {
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
		return sendPDPStatusFailureResponse(pdpUpdate, p, loggingPoliciesList, failureMessages)
	} else {
		return sendPDPStatusSuccessResponse(pdpUpdate, p, loggingPoliciesList)
	}
}

func sendPDPStatusFailureResponse(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender, loggingPoliciesList string, failureMessages []string) error {
	resMessage := fmt.Errorf("PDP Update Failed: %v", failureMessages)
	if err := sendFailureResponseVar(p, &pdpUpdate, resMessage); err != nil {
		log.Warnf("Failed to send update error response: %v", err)
		return err
	}
	return nil
}

func sendPDPStatusSuccessResponse(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender, loggingPoliciesList string) error {

	var resMessage string

	if len(pdpUpdate.PoliciesToBeDeployed) > 0 {
		resMessage = fmt.Sprintf("PDP Update Successful for all policies: %v", loggingPoliciesList)
		log.Infof("Processed policies_to_be_deployed successfully")
	} else if len(pdpUpdate.PoliciesToBeUndeployed) > 0 {
		resMessage = fmt.Sprintf("PDP Update Policies undeployed :%v", loggingPoliciesList)
		log.Infof("Processed policies_to_be_undeployed successfully")
	} else {
		resMessage = "PDP_UPDATE is successful"
	}

	if err := sendSuccessResponseVar(p, &pdpUpdate, resMessage); err != nil {
		log.Warnf("Failed to Send Update Response Message: %v", err)
		return err
	}
	return nil
}
