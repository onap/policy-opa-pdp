// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024: Deutsche Telecom
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
//   ========================LICENSE_END===================================

// kafkacomm package provides a structured way to create and manage Kafka consumers,
// handle subscriptions, and read messages from Kafka topics
package kafkacomm

import (
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/pkg/log"
	"time"
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
	kc.Consumer.Close()
}

// Unsubscribe unsubscribes the KafkaConsumer
func (kc *KafkaConsumer) Unsubscribe() error {
	if err := kc.Consumer.Unsubscribe(); err != nil {
		log.Warnf("Error Unsubscribing :%v", err)
		return err
	}
	log.Debug("Unsubscribe From Topic")
	return nil
}

// creates a new Kafka consumer and returns it
func NewKafkaConsumer() (*KafkaConsumer, error) {
	brokers := cfg.BootstrapServer
	groupid := cfg.GroupId
	topic := cfg.Topic
	useSASL := cfg.UseSASLForKAFKA
	username := cfg.KAFKA_USERNAME
	password := cfg.KAFKA_PASSWORD

	// Add Kafka Connection Properties ....
	configMap := &kafka.ConfigMap{
		"bootstrap.servers": brokers,
		"group.id":          groupid,
		"auto.offset.reset": "earliest",
	}
	//for STRIMZI-KAFKA in case sasl is enabled
	if useSASL == "true" {
		configMap.SetKey("sasl.mechanism", "SCRAM-SHA-512")
		configMap.SetKey("sasl.username", username)
		configMap.SetKey("sasl.password", password)
		configMap.SetKey("security.protocol", "SASL_PLAINTEXT")
	}

	// create new Kafka Consumer
	consumer, err := kafka.NewConsumer(configMap)
	if err != nil {
		log.Warnf("Error creating consumer: %v\n", err)
		return nil, err
	}
	//subscribe to topic
	err = consumer.SubscribeTopics([]string{topic}, nil)
	if err != nil {
		log.Warnf("Error subcribing to topic: %v\n", err)
		return nil, err
	}
	log.Debugf("Topic Subscribed... : %v", topic)
	return &KafkaConsumer{Consumer: consumer}, nil
}

// gets the Kafka messages on the subscribed topic
func ReadKafkaMessages(kc *KafkaConsumer) ([]byte, error) {
	msg, err := kc.Consumer.ReadMessage(-1)
	if err != nil {
		log.Warnf("Error reading Kafka message: %v", err)
		return nil, err
	}
	return msg.Value, nil
}
