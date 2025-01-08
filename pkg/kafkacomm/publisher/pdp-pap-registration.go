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

// allows to send the pdp registartion message with unique transaction id and timestamp to topic
package publisher

import (
	"encoding/json"
	"fmt"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/google/uuid"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpattributes"
	"time"
)

type PdpStatusSender interface {
	SendPdpStatus(pdpStatus model.PdpStatus) error
}

type RealPdpStatusSender struct {
	Producer kafkacomm.KafkaProducerInterface
}

// Sends PdpSTatus Message type to KafkaTopic
func (s *RealPdpStatusSender) SendPdpStatus(pdpStatus model.PdpStatus) error {

	var topic string
	topic = cfg.Topic
	pdpStatus.RequestID = uuid.New().String()
	pdpStatus.TimestampMs = fmt.Sprintf("%d", time.Now().UnixMilli())

	jsonMessage, err := json.Marshal(pdpStatus)
	if err != nil {
		log.Warnf("failed to marshal PdpStatus to JSON: %v", err)
		return err
	}
	log.Debugf("Producer saved in RealPdp StatusSender")

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

// sends the registartion message to topic using SendPdpStatus(pdpStatus)
func SendPdpPapRegistration(s PdpStatusSender) error {

	var pdpStatus = model.PdpStatus{
		MessageType: model.PDP_STATUS,
		PdpType:     consts.PdpType,
		State:       model.Passive,
		Healthy:     model.Healthy,
		Policies:    nil,
		PdpResponse: nil,
		Name:        pdpattributes.PdpName,
		Description: "Pdp Status Registration Message",
		PdpGroup:    consts.PdpGroup,
	}

	log.Debugf("Sending PDP PAP Registration Message")

	err := s.SendPdpStatus(pdpStatus)
	if err != nil {
		log.Warnf("Error producing message: %v\n", err)
		return err
	}
	return nil

}

