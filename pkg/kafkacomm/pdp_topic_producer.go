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
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"log"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"strings"
        "time"
)

type KafkaProducerInterface interface {
	Produce(*kafka.Message, chan kafka.Event) error
	Close()
	Flush(timeout int) int
}

// KafkaProducer wraps a Kafka producer instance and a topic to provide
// a simple interface for producing messages.
type KafkaProducer struct {
	producer KafkaProducerInterface
	topic    string
}

var (
	instance *KafkaProducer
)

// SafeTeardownProducer cleanly shuts down the producer singleton (idempotent).
func SafeTeardownProducer(kp *KafkaProducer) {
        if kp == nil || kp.producer == nil {
                log.Println("KafkaProducer or producer is nil, skipping SafeTeardownProducer.")
                return
        }
        // Flush outstanding messages
        kp.producer.Flush(consts.ProducerTearDownFlush)
        // Close underlying handle
        kp.producer.Close()
        log.Println("KafkaProducer safely torn down.")
}

// RebuildProducerSingleton tears down the current singleton and replaces it with a fresh one.
func RebuildProducerSingleton(topic string) (*KafkaProducer, error) {
        if instance != nil {
                log.Println("[Kafka] Rebuilding producer singleton: tearing down old handle...")
                SafeTeardownProducer(instance)
                instance = nil
                time.Sleep(consts.ProducerTearDownSleepTime) // small gap to let sockets close
        }
        // Create a brand-new singleton
        newInst, err := initializeKafkaProducer(topic)
        if err != nil {
                return nil, err
        }
        instance = newInst
        log.Println("[Kafka] Producer singleton rebuilt.")
        return instance, nil
}

// GetKafkaProducer initializes and returns a KafkaProducer instance which is a singleton.
// It configures the Kafka producer with the given bootstrap servers and topic.
// If SASL authentication is enabled via the configuration, the necessary credentials
// are set in the producer configuration.
//

func GetKafkaProducer(bootstrapServers, topic string) (*KafkaProducer, error) {
	var err error
        if instance != nil {
                log.Println("[Kafka] Existing producer singleton found; tearing down before re-init...")
                SafeTeardownProducer(instance)
                instance = nil
                time.Sleep(consts.ProducerTearDownSleepTime)
        }
	instance, err = initializeKafkaProducer(topic)
	return instance, err
}

//nolint:gosec
func initializeKafkaProducer(topic string) (*KafkaProducer, error) {
	brokers := cfg.BootstrapServer
	useSASL := cfg.UseSASLForKAFKA
	username := cfg.KAFKA_USERNAME
	password := cfg.KAFKA_PASSWORD

	configMap := &kafka.ConfigMap{
		"bootstrap.servers": brokers,
                "topic.metadata.refresh.interval.ms": consts.ProducerTopicMetadataRefresh,  // refresh every 30s
                "message.timeout.ms":                 consts.ProducerMessageTimeout, // 5 min delivery timeout
                "enable.idempotence":                 consts.ProducerEnableIdempotence,   // safe retries
                "delivery.timeout.ms":                consts.ProducerDeliveryTimeout, // 5 min
                "request.timeout.ms":                 consts.ProducerRequestTimeout,  // 30s
                "reconnect.backoff.ms":               consts.ProducerReconnectBackoff,    // initial backoff
                "reconnect.backoff.max.ms":           consts.ProducerReconnectBackoffMax,  // max backoff
	}

	if useSASL == "true" {
		configMap.SetKey("sasl.mechanism", "SCRAM-SHA-512")     // #nosec G104
		configMap.SetKey("sasl.username", username)             // #nosec G104
		configMap.SetKey("sasl.password", password)             // #nosec G104
		configMap.SetKey("security.protocol", "SASL_PLAINTEXT") // #nosec G104
	}

	p, err := kafka.NewProducer(configMap)
	if err != nil {
		return nil, err
	}

        // Delivery report listener
        go func() {
                for e := range p.Events() {
                        switch ev := e.(type) {
                        case *kafka.Message:
                                if ev.TopicPartition.Error == nil {
                                        log.Printf("[Kafka DR] Delivered: %v", ev.TopicPartition)
                                        continue
                                }

                                // Classify common delivery failures
                                if kerr, ok := ev.TopicPartition.Error.(kafka.Error); ok {
                                        switch kerr.Code() {
                                        case kafka.ErrMsgTimedOut:
                                                // Typical after a broker restart if the message exceeded delivery window
                                                log.Printf("[Kafka DR] Message timed out: %v", kerr)
                                        case kafka.ErrTransport:
                                                // Transient transport error during restart/flap
                                                log.Printf("[Kafka DR] Transport error: %v", kerr)
                                        case kafka.ErrUnknownTopicOrPart:
                                                log.Printf("[Kafka DR] Unknown topic/partition: %v (refreshing metadata)", kerr)
                                                // Refresh metadata to resolve stale leader/partition layout
                                                p.GetMetadata(nil, true, 5000)
                                                // If this persists, verify topic existence/ACLs via Admin/ops.
                                        default:
                                                log.Printf("[Kafka DR] Delivery failed: %v", kerr)
                                        }
                                } else {
                                        log.Printf("[Kafka DR] Delivery failed: %v", ev.TopicPartition.Error)
                                }
                        }
                }
        }()

	return &KafkaProducer{
		producer: p,
		topic:    topic,
	}, nil
}

// Produce sends a message to the configured Kafka topic.
// It takes the message payload as a byte slice and returns any errors
func (kp *KafkaProducer) Produce(kafkaMessage *kafka.Message, eventChan chan kafka.Event) error {
	log.Println("KafkaProducer or producer produce message")

	if kafkaMessage.TopicPartition.Topic == nil {
		kafkaMessage.TopicPartition = kafka.TopicPartition{
			Topic:     &kp.topic,
			Partition: kafka.PartitionAny,
		}
	}

	eventChan = nil
        maxRetries := consts.ProducerReconnectRetries
        var err error

        for attempt := 1; attempt <= maxRetries; attempt++ {
                err = kp.producer.Produce(kafkaMessage, eventChan)
                if err == nil {
                        return nil
                }

                // Handle local queue pressure quickly
                if kerr, ok := err.(kafka.Error); ok && kerr.Code() == kafka.ErrQueueFull {
                        log.Println("[Kafka Produce] queue full; flushing and backing off...")
                        // Drain delivery reports for up to 1s to make space
                        kp.producer.Flush(consts.ProducerFlushReportsTime)
                        time.Sleep(consts.ProducerTearDownSleepTime)
                        continue
                }

                // Classify the error (best effort). When Produce() returns an error,
                // it's usually a local issue (e.g., queue full), but we add rebuild logic
                // for common transport/auth cases observed during redeployments.
                var needsRebuild bool
                if kerr, ok := err.(kafka.Error); ok {
                        // Rebuild on fatal/auth/all-brokers-down errors
                        if kerr.IsFatal() ||
                                kerr.Code() == kafka.ErrAuthentication ||
                                kerr.Code() == kafka.ErrAllBrokersDown {
                                needsRebuild = true
                        }
                } else {
                        // Fallback string matching for transport/auth symptoms
                        emsg := strings.ToUpper(err.Error())
                        if strings.Contains(emsg, "AUTH") ||
                                strings.Contains(emsg, "BROKERS_DOWN") {
                                needsRebuild = true
                        }
                }

                log.Println("[Kafka Produce] Failed attempt", attempt, "/", maxRetries, ":", err)

                if needsRebuild {
                        log.Println("[Kafka Produce] Triggering producer rebuild due to error...")
                        // Rebuild global singleton and update this wrapper to use fresh handle
                        newInst, rerr := RebuildProducerSingleton(kp.topic)
                        if rerr != nil {
                                log.Println("[Kafka Produce] Rebuild failed:", rerr)
                                // Backoff before next attempt
                                time.Sleep(time.Second * time.Duration(attempt))
                                continue
                        }
                        // Point this wrapper to the new underlying producer
                        kp.producer = newInst.producer
                        log.Println("[Kafka Produce] Rebuild successful; retrying...")
                }

                // Backoff before next attempt
                time.Sleep(time.Second * time.Duration(attempt))
        }

        // Exhausted retries
        log.Println("[Kafka Produce] Failed after retries:", err)
        return err
}

// Close shuts down the Kafka producer, releasing all resources.
func (kp *KafkaProducer) Close() {

	if kp == nil || kp.producer == nil {
		log.Println("KafkaProducer or producer is nil, skipping Close.")
		return
	}
	kp.producer.Flush(consts.ProducerTearDownFlush)
	kp.producer.Close()
	log.Println("KafkaProducer closed successfully.")
}

func (kp *KafkaProducer) Flush(timeout int) int {
	return kp.producer.Flush(consts.ProducerTearDownFlush)
}
