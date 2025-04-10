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
//

// responsible for sending PDP_STATUS messages in response to specific events
// such as updates (PDP_UPDATE) or state changes (PDP_STATE_CHANGE). These responses provide details
// about the current state, health, and attributes of the Policy Decision Point (PDP).
package publisher

import (
	"fmt"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpattributes"
	"policy-opa-pdp/pkg/pdpstate"
	"policy-opa-pdp/pkg/policymap"
	"time"

	"github.com/google/uuid"
)

type(
	SendPdpUpdateResponseFunc func(s PdpStatusSender, pdpUpdate *model.PdpUpdate, resMessage string) error
)

var (
	SendPdpUpdateResponseVar SendPdpUpdateResponseFunc = SendPdpUpdateResponse
)

// Sends a PDP_STATUS message to indicate the successful processing of a PDP_UPDATE request
// received from the Policy Administration Point (PAP).
func SendPdpUpdateResponse(s PdpStatusSender, pdpUpdate *model.PdpUpdate, resMessage string) error {

	responseStatus := model.Success
	responseMessage := resMessage

	pdpStatus := model.PdpStatus{
		MessageType: model.PDP_STATUS,
		PdpType:     consts.PdpType,
		State:       pdpstate.State,
		Healthy:     model.Healthy,
		Name:        pdpattributes.PdpName,
		Description: "Pdp Status Response Message For Pdp Update",
		PdpGroup:    consts.PdpGroup,
		PdpSubgroup: &pdpattributes.PdpSubgroup,
		Policies:    []model.ToscaConceptIdentifier{},
		PdpResponse: &model.PdpResponseDetails{
			ResponseTo:      &pdpUpdate.RequestId,
			ResponseStatus:  &responseStatus,
			ResponseMessage: &responseMessage,
		},
	}

	pdpStatus.RequestID = uuid.New().String()
	pdpStatus.TimestampMs = fmt.Sprintf("%d", time.Now().UnixMilli())

	policiesMap := policymap.LastDeployedPolicies

	if policiesMap != "" {
		if (policymap.ExtractDeployedPolicies(policiesMap)) == nil {
			log.Warnf("No Policies extracted from Policy Map")
		} else {
			pdpStatus.Policies = policymap.ExtractDeployedPolicies(policiesMap)
		}
	}

	log.Infof("Sending PDP Status With Update Response")

	err := s.SendPdpStatus(pdpStatus)
	if err != nil {
		log.Warnf("Failed to send PDP Update Message : %v", err)
		return err
	}

	return nil

}

func SendPdpUpdateErrorResponse(s PdpStatusSender, pdpUpdate *model.PdpUpdate, err error) error {

	responseStatus := model.Failure
	responseMessage := fmt.Sprintf("%v", err)

	pdpStatus := model.PdpStatus{
		MessageType: model.PDP_STATUS,
		PdpType:     consts.PdpType,
		State:       pdpstate.State,
		Healthy:     model.Healthy,
		Name:        pdpattributes.PdpName,
		Description: "Pdp Status Response Message For Pdp Update",
		PdpGroup:    consts.PdpGroup,
		PdpSubgroup: &pdpattributes.PdpSubgroup,
		Policies:    []model.ToscaConceptIdentifier{},
		PdpResponse: &model.PdpResponseDetails{
			ResponseTo:      &pdpUpdate.RequestId,
			ResponseStatus:  &responseStatus,
			ResponseMessage: &responseMessage,
		},
	}

	pdpStatus.RequestID = uuid.New().String()
	pdpStatus.TimestampMs = fmt.Sprintf("%d", time.Now().UnixMilli())

	policiesMap := policymap.LastDeployedPolicies

	if policiesMap != "" {
		if (policymap.ExtractDeployedPolicies(policiesMap)) == nil {
			log.Warnf("No Policies extracted from Policy Map")
		} else {
			pdpStatus.Policies = policymap.ExtractDeployedPolicies(policiesMap)
		}
	}

	log.Infof("Sending PDP Status With Update Error Response")

	err = s.SendPdpStatus(pdpStatus)
	if err != nil {
		log.Warnf("Failed to send PDP Update Error Message : %v", err)
		return err
	}

	return nil

}

// Sends a PDP_STATUS message to indicate a state change in the PDP (e.g., from PASSIVE to ACTIVE).
func SendStateChangeResponse(s PdpStatusSender, pdpStateChange *model.PdpStateChange) error {

	responseStatus := model.Success
	responseMessage := "PDP State Changed From PASSIVE TO Active"
	pdpStatus := model.PdpStatus{
		MessageType: model.PDP_STATUS,
		PdpType:     consts.PdpType,
		State:       pdpstate.GetState(),
		Healthy:     model.Healthy,
		Name:        pdpattributes.PdpName,
		Description: "Pdp Status Response Message to Pdp State Change",
		PdpGroup:    consts.PdpGroup,
		PdpSubgroup: &pdpattributes.PdpSubgroup,
		Policies:    []model.ToscaConceptIdentifier{},
		PdpResponse: &model.PdpResponseDetails{
			ResponseTo:      &pdpStateChange.RequestId,
			ResponseStatus:  &responseStatus,
			ResponseMessage: &responseMessage,
		},
	}

	pdpStatus.RequestID = uuid.New().String()
	pdpStatus.TimestampMs = fmt.Sprintf("%d", time.Now().UnixMilli())

	log.Infof("Sending PDP Status With State Change response")

	err := s.SendPdpStatus(pdpStatus)
	if err != nil {
		log.Warnf("Failed to send PDP State Change Message : %v", err)
		return err
	}

	return nil
}
