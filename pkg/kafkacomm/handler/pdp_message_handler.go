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

// The handler package is responsible for processing messages from Kafka, specifically targeting the OPA
// (Open Policy Agent) PDP (Policy Decision Point). It validates the message type,
//
//	ensures it is relevant to the current PDP, and dispatches the message for appropriate processing.
package handler

import (
	"context"
	"encoding/json"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/pdpattributes"
	"strings"
	"sync"
	"time"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

type (
	pdpUpdateMessageHandlerFunc      func(message []byte, p publisher.PdpStatusSender) error
	pdpStateChangeMessageHandlerFunc func(message []byte, p publisher.PdpStatusSender) error
)

var (
	shutdownFlag                    bool
	mu                              sync.Mutex
	pdpUpdateMessageHandlerVar      pdpUpdateMessageHandlerFunc      = pdpUpdateMessageHandler
	pdpStateChangeMessageHandlerVar pdpStateChangeMessageHandlerFunc = pdpStateChangeMessageHandler
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
		// Message is targeted by name
		return message.Name == pdpattributes.PdpName
	}

	// Message is a broadcast; validate group and subGroup rules
	if message.PdpGroup == "" {
		return false
	}

	if pdpattributes.PdpSubgroup == "" {
		// This PDP has no subgroup assignment; ignore broadcast messages
		return false
	}

	if message.PdpGroup != consts.PdpGroup {
		return false
	}

	if message.PdpSubgroup == "" {
		//Broadcast to entire group
		return true
	}

	// Broadcast within subgroup
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

		default:
			message, err := kafkacomm.ReadKafkaMessages(kc)
			if err != nil {
                                if shouldRebuildConsumer(err) {
                                        log.Warnf("Consumer error; rebuilding. err=%v", err)
                                        log.Info("Recovering Kafka Consumer......")
                                        newKc, recErr := recoverConsumer(kc, topic, cfg.GroupId)
                                        if recErr == nil && newKc != nil {
                                                kc = newKc
                                                log.Info("New consumer initialized")
                                        } else {
                                                log.Warnf("Failed to re-initialize consumer: %v", recErr)
                                                time.Sleep(consts.ConsumerPollSleep)
                                        }
                                        continue
                                }
                                // Non-fatal/non-rebuild errors: small backoff and continue
                                consumerNonFatalBackoff()
				continue
			}


                        if message == nil {
                                continue
                        }

			log.Debugf("[IN|KAFKA|%s]\n%s", topic, string(message))

			var opaPdpMessage OpaPdpMessage

                        if err := json.Unmarshal(message, &opaPdpMessage); err != nil {
				log.Warnf("Failed to UnMarshal Messages: %v\n", err)
				continue
			}

			if !checkIfMessageIsForOpaPdp(opaPdpMessage) {
				log.Warnf("Not a valid Opa Pdp Message")
				continue
			}

			handlePdpMessageTypes(opaPdpMessage.MessageType, message, p)
		}

	}
	return nil

}

func handlePdpMessageTypes(messageType string, message []byte, p publisher.PdpStatusSender) {
	log.Debugf("messageType: %s", messageType)

	switch messageType {
	case "PDP_UPDATE":
		if err := pdpUpdateMessageHandlerVar(message, p); err != nil {
			log.Warnf("Error processing Update Message: %v", err)
		}

	case "PDP_STATE_CHANGE":
		if err := pdpStateChangeMessageHandlerVar(message, p); err != nil {
			log.Warnf("Error processing State Change Message: %v", err)
		}

	case "PDP_STATUS":
		log.Debugf("discarding event of type PDP_STATUS")
	default:
		log.Errorf("This is not a valid Message Type: %s", messageType)
	}
}

// ------------------------
// Helper methods (same file)
// ------------------------

// shouldRebuildConsumer determines if the consumer must be torn down and recreated
// based on the error returned by the Kafka client.
func shouldRebuildConsumer(err error) bool {
        if err == nil {
                return false
        }

        // Prefer structured kafka.Error classification
        if ke, ok := err.(kafka.Error); ok {
                // Fatal errors, all brokers down, or authentication errors require rebuild
                if ke.IsFatal() || ke.Code() == kafka.ErrAllBrokersDown || ke.Code() == kafka.ErrAuthentication {
                        return true
                }
                // Otherwise, treat as non-fatal/transient
                return false
        }

        // Fallback heuristic based on error text for non-kafka.Error cases
        txt := strings.ToUpper(err.Error())
        if strings.Contains(txt, "AUTH") || strings.Contains(txt, "BROKERS_DOWN") {
                return true
        }

        return false
}

// recoverConsumer encapsulates teardown + recreation of the Kafka consumer.
// It uses the kafkacomm.SafeTeardown and NewKafkaConsumer in sequence, with a small cooldown
// to let sockets close cleanly.
func recoverConsumer(kc *kafkacomm.KafkaConsumer, topic, groupID string) (*kafkacomm.KafkaConsumer, error) {
        // Teardown current handle
        kafkacomm.SafeTeardown(kc)

        // Small cooldown to allow sockets to close
        time.Sleep(consts.ConsumerReconnectRetries)

        // Recreate with latest config (e.g., group.id)
        return kafkacomm.NewKafkaConsumer(topic, groupID)
}

// consumerNonFatalBackoff applies a small delay for transient/non-fatal errors.
func consumerNonFatalBackoff() {
        time.Sleep(consts.ConsumerTearDownSleepTime)
}
