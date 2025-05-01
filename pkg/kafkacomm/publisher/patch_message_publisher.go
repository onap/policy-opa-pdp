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

package publisher

import (
	"encoding/json"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/cfg"
)

type RealPatchSender struct {
	Producer kafkacomm.KafkaProducerInterface
}

type PatchKafkaPayload struct {
	PatchInfos []opasdk.PatchImpl `json:"patchInfos"`
}

func (s *RealPatchSender) SendPatchMessage(patchInfos []opasdk.PatchImpl) error {
	log.Debugf("In SendPatchMessage")
	var topic string
	topic = cfg.PatchTopic
	kafkaPayload := PatchKafkaPayload{
		PatchInfos: patchInfos,
	}

	jsonMessage, err := json.Marshal(kafkaPayload)
	if err != nil {
		log.Warnf("failed to marshal Patch Payload to JSON: %v", err)
		return err
	}

	kafkaMessage := &kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic:     &topic,
			Partition: kafka.PartitionAny,
		},
		Value: jsonMessage,
	}
	var eventChan chan kafka.Event = nil
	err = s.Producer.Produce(kafkaMessage, eventChan)
	if err != nil {
		log.Warnf("Error producing message: %v\n", err)
		return err
	} else {
		log.Debugf("[OUT|KAFKA|%s]\n%s", topic, string(jsonMessage))
	}

	return nil
}
