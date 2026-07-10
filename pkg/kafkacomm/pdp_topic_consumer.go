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

// kafkacomm package provides a structured way to create and manage Kafka consumers,
// handle subscriptions, and read messages from Kafka topics
package kafkacomm

import (
	"fmt"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"time"
)

// SafeTeardown closes a consumer with unsubscribe first (idempotent).
func SafeTeardown(kc *KafkaConsumer) {
	if kc == nil || kc.Consumer == nil {
		return
	}
	if err := kc.Consumer.Unsubscribe(); err != nil {
		log.Warnf("Error Unsubscribing during teardown: %v", err)
	}
	if err := kc.Consumer.Close(); err != nil {
		log.Warnf("Error Closing consumer during teardown: %v", err)
	}
}

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
func (kc *KafkaConsumer) Close() error {
	if kc.Consumer != nil {
		if err := kc.Consumer.Close(); err != nil {
			return fmt.Errorf("failed to close consumer: %v", err)
		}
	}
	return nil
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

type KafkaNewConsumerFunc func(*kafka.ConfigMap) (*kafka.Consumer, error)

var KafkaNewConsumer KafkaNewConsumerFunc = kafka.NewConsumer

// NewKafkaConsumer creates a new Kafka consumer and returns a fresh independent
// instance. Each call returns its own handle; no package-global is used or torn down.
func NewKafkaConsumer(topic string, groupid string) (*KafkaConsumer, error) {
	log.Debugf("Creating Kafka Consumer instance for topic %v", topic)
	brokers := cfg.BootstrapServer
	useSASL := cfg.UseSASLForKAFKA
	username := cfg.KAFKA_USERNAME
	password := cfg.KAFKA_PASSWORD

	// Add Kafka connection properties
	configMap := &kafka.ConfigMap{
		"bootstrap.servers":                  brokers,
		"group.id":                           groupid,
		"auto.offset.reset":                  "latest",
		"session.timeout.ms":                 consts.ConsumerSessionTimeout,
		"max.poll.interval.ms":               consts.ConsumerMaxPoll,
		"enable.auto.commit":                 consts.ConsumerAutoCommit,
		"enable.partition.eof":               consts.ConsumerPartitionEOF,
		"reconnect.backoff.ms":               consts.ConsumerBackoffMIN,
		"reconnect.backoff.max.ms":           consts.ConsumerBackoffMAX,
		"topic.metadata.refresh.interval.ms": consts.ConsumerTopicMetadata,
		"socket.receive.buffer.bytes":        consts.ConsumerSocketReceive,
		"max.partition.fetch.bytes":          consts.ConsumerMaxPartitionFetch,
		"fetch.max.bytes":                    consts.ConsumerFetchMaxBytes,
	}
	// If SASL is enabled, add SASL properties
	if useSASL == "true" {
		configMap.SetKey("sasl.mechanism", "SCRAM-SHA-512")     // #nosec G104
		configMap.SetKey("sasl.username", username)             // #nosec G104
		configMap.SetKey("sasl.password", password)             // #nosec G104
		configMap.SetKey("security.protocol", "SASL_PLAINTEXT") // #nosec G104
		// configMap.SetKey("debug", "all") // Uncomment for debug
	}

	consumer, err := KafkaNewConsumer(configMap)
	if err != nil {
		log.Warnf("Error creating consumer: %v", err)
		return nil, fmt.Errorf("error creating consumer: %w", err)
	}
	if consumer == nil {
		log.Warnf("Kafka Consumer is nil after creation")
		return nil, fmt.Errorf("Kafka Consumer is nil after creation")
	}

	if err = consumer.SubscribeTopics([]string{topic}, nil); err != nil {
		log.Warnf("Error subscribing to topic: %v", err)
		return nil, fmt.Errorf("error subscribing to topic: %w", err)
	}
	log.Debugf("Topic Subscribed: %v", topic)

	return &KafkaConsumer{Consumer: consumer}, nil
}

// ReadKafkaMessages gets the Kafka messages on the subscribed topic
func ReadKafkaMessages(kc *KafkaConsumer) ([]byte, error) {
	msg, err := kc.Consumer.ReadMessage(100 * time.Millisecond)
	if err != nil {
		if kafkaErr, ok := err.(kafka.Error); ok {
			switch kafkaErr.Code() {
			case kafka.ErrTimedOut:
				return nil, err // no message, normal
			case kafka.ErrAllBrokersDown:
				log.Warn("All brokers down. Retrying after backoff...")
				time.Sleep(consts.ConsumerReconnectRetries)
				return nil, err
			default:
				log.Errorf("Kafka error: %v", kafkaErr)
			}
		}
		return nil, err
	}

	return msg.Value, nil
}
