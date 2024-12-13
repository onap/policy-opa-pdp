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

// kafkacomm package provides a structured way to create and manage Kafka consumers,
// handle subscriptions, and read messages from Kafka topics
package kafkacomm

import (
	"fmt"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/pkg/log"
	"sync"
	"time"
)

var (
	// Declare a global variable to hold the singleton KafkaConsumer
	consumerInstance *KafkaConsumer
	consumerOnce     sync.Once // sync.Once ensures that the consumer is created only once
)

// KafkaConsumerInterface defines the interface for a Kafka consumer.
type KafkaConsumerInterface interface {
	Close() error
	Unsubscribe() error
	ReadMessage(timeout time.Duration) (*kafka.Message, error)
}

// KafkaConsumer is a wrapper around the Kafka consumer.
type KafkaConsumer struct {
	Consumer KafkaConsumerInterface
}

// Close closes the KafkaConsumer
func (kc *KafkaConsumer) Close() {
	if kc.Consumer != nil {
		kc.Consumer.Close()
	}
}

// Unsubscribe unsubscribes the KafkaConsumer
func (kc *KafkaConsumer) Unsubscribe() error {
	if kc.Consumer == nil {
		return fmt.Errorf("Kafka Consumer is nil so cannot Unsubscribe")
	}
	err := kc.Consumer.Unsubscribe()
	if err != nil {
		log.Warnf("Error Unsubscribing: %v", err)
		return err
	}
	log.Debug("Unsubscribed From Topic")
	return nil
}

// NewKafkaConsumer creates a new Kafka consumer and returns it
func NewKafkaConsumer() (*KafkaConsumer, error) {
	// Initialize the consumer instance only once
	consumerOnce.Do(func() {
		log.Debugf("Creating Kafka Consumer singleton instance")
		brokers := cfg.BootstrapServer
		groupid := cfg.GroupId
		topic := cfg.Topic
		useSASL := cfg.UseSASLForKAFKA
		username := cfg.KAFKA_USERNAME
		password := cfg.KAFKA_PASSWORD

		// Add Kafka connection properties
		configMap := &kafka.ConfigMap{
			"bootstrap.servers": brokers,
			"group.id":          groupid,
			"auto.offset.reset": "latest",
		}

		// If SASL is enabled, add SASL properties
		if useSASL == "true" {
			configMap.SetKey("sasl.mechanism", "SCRAM-SHA-512")
			configMap.SetKey("sasl.username", username)
			configMap.SetKey("sasl.password", password)
			configMap.SetKey("security.protocol", "SASL_PLAINTEXT")
			configMap.SetKey("session.timeout.ms", "30000")
			configMap.SetKey("max.poll.interval.ms", "300000")
			configMap.SetKey("enable.partition.eof", true)
			configMap.SetKey("enable.auto.commit", true)
			// configMap.SetKey("debug", "all") // Uncomment for debug
		}

		// Create a new Kafka consumer
		consumer, err := kafka.NewConsumer(configMap)
		if err != nil {
			log.Warnf("Error creating consumer: %v", err)
			return
		}
		if consumer == nil {
			log.Warnf("Kafka Consumer is nil after creation")
			return
		}

		// Subscribe to the topic
		err = consumer.SubscribeTopics([]string{topic}, nil)
		if err != nil {
			log.Warnf("Error subscribing to topic: %v", err)
			return
		}
		log.Debugf("Topic Subscribed: %v", topic)

		// Assign the consumer instance
		consumerInstance = &KafkaConsumer{Consumer: consumer}
		log.Debugf("Created SIngleton consumer instance")
	})

	// Return the singleton consumer instance
	if consumerInstance == nil {
		return nil, fmt.Errorf("Kafka Consumer instance not created")
	}
	return consumerInstance, nil
}

// ReadKafkaMessages gets the Kafka messages on the subscribed topic
func ReadKafkaMessages(kc *KafkaConsumer) ([]byte, error) {
	msg, err := kc.Consumer.ReadMessage(100 * time.Millisecond)
	if err != nil {
		return nil, err
	}
	return msg.Value, nil
}
