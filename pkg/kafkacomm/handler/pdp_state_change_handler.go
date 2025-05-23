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

// will process the state change message from pap and send the pdp status response.
package handler

import (
	"encoding/json"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpstate"
)

// Processes incoming messages indicating a PDP state change.
// This includes updating the PDP state and sending a status response when the state transitions.
func pdpStateChangeMessageHandler(message []byte, p publisher.PdpStatusSender) error {

	var pdpStateChange model.PdpStateChange

	err := json.Unmarshal(message, &pdpStateChange)
	if err != nil {
		log.Debugf("Failed to UnMarshal Messages: %v\n", err)
		return err
	}

	log.Debugf("PDP STATE CHANGE message received: %s", string(message))

	if pdpStateChange.State != "" {
		err := pdpstate.SetState(pdpStateChange.State)
		if err != nil {
			log.Errorf("Failed to set PDP state: %v", err)
			return err // or handle the error as appropriate
		}

	}

	log.Debugf("State change from PASSIVE To : %s", pdpstate.GetState())
	err = publisher.SendStateChangeResponse(p, &pdpStateChange)
	if err != nil {
		log.Debugf("Failed to Send State Change Response Message: %v\n", err)
		return err
	}
	log.Infof("PDP_STATUS With State Change Message Sent Successfully")

	return nil
}
