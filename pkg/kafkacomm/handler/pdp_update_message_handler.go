// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024: Deutsche Telecom
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
//   ========================LICENSE_END===================================

// will process the update message from pap and send the pdp status response.
package handler

import (
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpattributes"
)

// Handles messages of type PDP_UPDATE sent from the Policy Administration Point (PAP).
// It validates the incoming data, updates PDP attributes, and sends a response back to the sender.
func PdpUpdateMessageHandler(message []byte, p publisher.PdpStatusSender) error {

	var pdpUpdate model.PdpUpdate
	err := json.Unmarshal(message, &pdpUpdate)
	if err != nil {
		log.Debugf("Failed to UnMarshal Messages: %v\n", err)
		return err
	}
	//Initialize Validator and validate Struct after unmarshalling
	validate := validator.New()

	err = validate.Struct(pdpUpdate)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			log.Infof("Field %s failed on the %s tag\n", err.Field(), err.Tag())
		}
		return err
	}

	log.Debugf("PDP_UPDATE Message received: %s", string(message))

	pdpattributes.SetPdpSubgroup(pdpUpdate.PdpSubgroup)
	pdpattributes.SetPdpHeartbeatInterval(pdpUpdate.PdpHeartbeatIntervalMs)

	err = publisher.SendPdpUpdateResponse(p, &pdpUpdate)
	if err != nil {
		log.Debugf("Failed to Send Update Response Message: %v\n", err)
		return err
	}
	log.Infof("PDP_STATUS Message Sent Successfully")
	go publisher.StartHeartbeatIntervalTimer(pdpattributes.PdpHeartbeatInterval, p)
	return nil
}
