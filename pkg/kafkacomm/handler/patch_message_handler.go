// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024-2026: Deutsche Telekom
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

package handler

import (
	"context"
	"encoding/json"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"go.opentelemetry.io/otel/codes"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/data"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"time"
)

var (
	recoverConsumerVar = recoverConsumer
)

// PatchMessageHandler handles incoming Kafka messages and dispatches them for data patch processing.
// Error handling is delegated to helper functions in this same file:
//   - shouldRebuildConsumer(err error) bool
//   - recoverConsumerVar(kc *kafkacomm.KafkaConsumer, topic, groupID string) (*kafkacomm.KafkaConsumer, error)
//   - consumerNonFatalBackoff()
func PatchMessageHandler(ctx context.Context, kc *kafkacomm.KafkaConsumer, topic string) error {
	log.Debug("Starting Patch Message Listener.....")
	for {
		select {
		case <-ctx.Done():
			log.Debug("Stopping PDP Listener.....")
			return nil
		default:
			msg, err := kafkacomm.ReadKafkaMessages(kc)
			if err != nil {
				if shouldRebuildConsumer(err) {
					log.Warnf("Consumer error; rebuilding. err=%v", err)
					log.Info("Recovering Kafka Consumer......")
					newKc, recErr := recoverConsumerVar(kc, topic, cfg.GroupId)
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

			if msg == nil {
				continue
			}
			message := msg.Value

			log.Debugf("[IN|KAFKA|%s]\n%s", topic, string(message))

			var patchMsg model.PatchMessage
			if err := json.Unmarshal(message, &patchMsg); err != nil {
				log.Warnf("Failed to UnMarshal PatchMessage: %v\n", err)
				continue
			}
			log.Debugf("Received patch request")

			// check message type
			if patchMsg.Header.MessageType != model.OPA_PDP_DATA_PATCH_SYNC.String() {
				log.Warnf("Ignoring message with unexpected type: %s", patchMsg.Header.MessageType)
				continue
			}

			log.Debugf("Received patch request from source: %s", patchMsg.Header.SourceID)

			applyPatch(ctx, topic, msg, patchMsg)
		}
	}
}

// applyPatch applies a broadcast data patch inside a consumer span that continues
// the trace of the replica which published it, so a fan-out patch appears as one
// trace across all replicas rather than one orphan trace per replica.
func applyPatch(ctx context.Context, topic string, msg *kafka.Message, patchMsg model.PatchMessage) {
	_, span := startConsumerSpan(ctx, topic, msg, patchMsg.Header.MessageType)
	defer span.End()

	if err := data.PatchDataVar(patchMsg.PatchInfos, nil); err != nil {
		log.Debugf("patchData failed: %v", err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	log.Debugf("Successfully patched data")
}
