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

// Package kafkacomm provides utilities for producing messages to a Kafka topic
// using a configurable Kafka producer. It supports SASL authentication and
// dynamic topic configuration.
package kafkacomm

import (
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"log"
	"policy-opa-pdp/cfg"
	"sync"
)

type KafkaProducerInterface interface {
	Produce(*kafka.Message, chan kafka.Event) error
	Close()
}

// KafkaProducer wraps a Kafka producer instance and a topic to provide
// a simple interface for producing messages.
type KafkaProducer struct {
	producer KafkaProducerInterface
	topic    string
}

var (
	instance *KafkaProducer
	once     sync.Once
)

// GetKafkaProducer initializes and returns a KafkaProducer instance which is a singleton.
// It configures the Kafka producer with the given bootstrap servers and topic.
// If SASL authentication is enabled via the configuration, the necessary credentials
// are set in the producer configuration.
func GetKafkaProducer(bootstrapServers, topic string) (*KafkaProducer, error) {
	var err error
	once.Do(func() {
		brokers := cfg.BootstrapServer
		useSASL := cfg.UseSASLForKAFKA
		username := cfg.KAFKA_USERNAME
		password := cfg.KAFKA_PASSWORD

		// Add Kafka Connection Properties ....
		configMap := &kafka.ConfigMap{
			"bootstrap.servers": brokers,
		}

		if useSASL == "true" {
			configMap.SetKey("sasl.mechanism", "SCRAM-SHA-512")
			configMap.SetKey("sasl.username", username)
			configMap.SetKey("sasl.password", password)
			configMap.SetKey("security.protocol", "SASL_PLAINTEXT")
		}

		p, err := kafka.NewProducer(configMap)
		if err != nil {
			return
		}
		instance = &KafkaProducer{
			producer: p,
			topic:    topic,
		}

	})
	return instance, err
}

// Produce sends a message to the configured Kafka topic.
// It takes the message payload as a byte slice and returns any errors
func (kp *KafkaProducer) Produce(kafkaMessage *kafka.Message, eventChan chan kafka.Event) error {
	if kafkaMessage.TopicPartition.Topic == nil {
		kafkaMessage.TopicPartition = kafka.TopicPartition{
			Topic:     &kp.topic,
			Partition: kafka.PartitionAny,
		}
	}
	eventChan = nil
	err := kp.producer.Produce(kafkaMessage, eventChan)
	if err != nil {
		return err
	}
	return nil
}

// Close shuts down the Kafka producer, releasing all resources.
func (kp *KafkaProducer) Close() {

	if kp == nil || kp.producer == nil {
		log.Println("KafkaProducer or producer is nil, skipping Close.")
		return
	}
	kp.producer.Close()
	log.Println("KafkaProducer closed successfully.")
}
