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
//

package handler


import (
	"context"
	"encoding/json"
	"policy-opa-pdp/pkg/data"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
)


// This function handles the incoming kafka messages and dispatches them futher for data patch processing.
func PatchMessageHandler(ctx context.Context, kc *kafkacomm.KafkaConsumer, topic string) error {
	log.Debug("Starting Patch Message Listener.....")
	for {
		select {
		case <-ctx.Done():
			log.Debug("Stopping PDP Listener.....")
			return nil
		default:
			message, err := kafkacomm.ReadKafkaMessages(kc)
			if err != nil {
				continue
			}
			log.Debugf("[IN|KAFKA|%s]\n%s", topic, string(message))

			if message != nil {
				var patchMsg model.PatchMessage
				err = json.Unmarshal(message, &patchMsg)
				if err != nil {
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

				if err := data.PatchDataVar(patchMsg.PatchInfos, nil); err != nil {
					log.Debugf("patchData failed: %v", err)
				} else {
					log.Debugf("Successfully patched data")
				}
			}
		}
	}
}

