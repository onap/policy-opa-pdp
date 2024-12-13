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

// The handler package is responsible for processing messages from Kafka, specifically targeting the OPA
// (Open Policy Agent) PDP (Policy Decision Point). It validates the message type,
//
//	ensures it is relevant to the current PDP, and dispatches the message for appropriate processing.
package handler

import (
	"context"
	"encoding/json"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/pdpattributes"
	"sync"
)

var (
	shutdownFlag bool
	mu           sync.Mutex
)

// SetShutdownFlag sets the shutdown flag
func SetShutdownFlag() {
	mu.Lock()
	shutdownFlag = true
	mu.Unlock()
}

// IsShutdown checks if the consumer has already been shut down
func IsShutdown() bool {
	mu.Lock()
	defer mu.Unlock()
	return shutdownFlag
}

type OpaPdpMessage struct {
	Name        string `json:"name"`        // Name of the PDP (optional for broadcast messages).
	MessageType string `json:"MessageName"` // Type of the message (e.g., PDP_UPDATE, PDP_STATE_CHANGE, etc.)
	PdpGroup    string `json:"pdpGroup"`    // Group to which the PDP belongs.
	PdpSubgroup string `json:"pdpSubgroup"` // Subgroup within the PDP group.
}

// Checks if the incoming Kafka message belongs to the current PDP instance.
func checkIfMessageIsForOpaPdp(message OpaPdpMessage) bool {

	if message.Name != "" {
		// message included a PDP name, check if matches
		//log.Infof(" Message Name is not empty")
		return message.Name == pdpattributes.PdpName
	}

	// message does not provide a PDP name - must be a broadcast
	if message.PdpGroup == "" {
		//log.Infof(" Message PDP Group is empty")
		return false
	}

	if pdpattributes.PdpSubgroup == "" {
		// this PDP has no assignment yet, thus should ignore broadcast messages
		//log.Infof(" pdpstate PDP subgroup is empty")
		return false
	}

	if message.PdpGroup != consts.PdpGroup {
		//log.Infof(" message pdp group is not equal to cons pdp group")
		return false
	}

	if message.PdpSubgroup == "" {
		//message was broadcast to entire group
		//log.Infof(" message pdp subgroup is empty")
		return true
	}

	return message.PdpSubgroup == pdpattributes.PdpSubgroup
}

// Handles incoming Kafka messages, validates their relevance to the current PDP,
// and dispatches them for further processing based on their type.
func PdpMessageHandler(ctx context.Context, kc *kafkacomm.KafkaConsumer, topic string, p publisher.PdpStatusSender) error {

	log.Debug("Starting PDP Message Listener.....")
	var stopConsuming bool
	for !stopConsuming {
		select {
		case <-ctx.Done():
			log.Debug("Stopping PDP Listener.....")
			return nil
			stopConsuming = true ///Loop Exits
		default:
			message, err := kafkacomm.ReadKafkaMessages(kc)
			if err != nil {
				continue
			}
			log.Debugf("[IN|KAFKA|%s]\n%s", topic, string(message))

			if message != nil {

				var opaPdpMessage OpaPdpMessage

				err = json.Unmarshal(message, &opaPdpMessage)
				if err != nil {
					log.Warnf("Failed to UnMarshal Messages: %v\n", err)
					continue
				}

				if !checkIfMessageIsForOpaPdp(opaPdpMessage) {

					log.Warnf("Not a valid Opa Pdp Message")
					continue
				}

				switch opaPdpMessage.MessageType {

				case "PDP_UPDATE":
					err = PdpUpdateMessageHandler(message, p)
					if err != nil {
						log.Warnf("Error processing Update Message: %v", err)
					}

				case "PDP_STATE_CHANGE":
					err = PdpStateChangeMessageHandler(message, p)
					if err != nil {
						log.Warnf("Error processing Update Message: %v", err)
					}

				case "PDP_STATUS":
					log.Debugf("discarding event of type PDP_STATUS")
					continue
				default:
					log.Errorf("This is not a valid Message Type: %s", opaPdpMessage.MessageType)
					continue

				}

			}
		}

	}
	return nil

}
