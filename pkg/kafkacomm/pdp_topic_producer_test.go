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
//

package kafkacomm

import (
	"bytes"
	"errors"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"log"
	"policy-opa-pdp/cfg"
	"testing"
	"time"

	"policy-opa-pdp/pkg/kafkacomm/mocks" // Adjust to your actual mock path
)

func TestKafkaProducer_Produce_Success(t *testing.T) {
	done := make(chan struct{})

	go func() {
		defer close(done)
		// Arrange
		mockProducer := new(mocks.KafkaProducerInterface)
		topic := "test-topic"
		kp := &KafkaProducer{
			producer: mockProducer,
			topic:    topic,
		}

		message := []byte("test message")

		kafkaMessage := &kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &topic,
				Partition: kafka.PartitionAny,
			},
			Value: message,
		}
		var eventChan chan kafka.Event = nil

		// Mock Produce method to simulate successful delivery
		mockProducer.On("Produce", mock.Anything, mock.Anything).Return(nil)

		// Act
		err := kp.Produce(kafkaMessage, eventChan)

		assert.NoError(t, err)
		mockProducer.AssertExpectations(t)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("test timed out")
	}

}

func TestKafkaProducer_Produce_Error(t *testing.T) {
	// Arrange
	mockProducer := new(mocks.KafkaProducerInterface)
	topic := "test-topic"
	kp := &KafkaProducer{
		producer: mockProducer,
		topic:    topic,
	}

	// Simulate production error
	mockProducer.On("Produce", mock.Anything, mock.Anything).Return(errors.New("produce error"))

	message := []byte("test message")

	kafkaMessage := &kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic:     &topic,
			Partition: kafka.PartitionAny,
		},
		Value: message,
	}
	var eventChan chan kafka.Event = nil

	// Act
	err := kp.Produce(kafkaMessage, eventChan)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, "produce error", err.Error())
	mockProducer.AssertExpectations(t)
}

func TestKafkaProducer_Close(t *testing.T) {
	// Arrange
	mockProducer := new(mocks.KafkaProducerInterface)
	kp := &KafkaProducer{
		producer: mockProducer,
	}

	// Simulate successful close
	mockProducer.On("Close").Return()

	// Act
	kp.Close()

	// Assert
	mockProducer.AssertExpectations(t)
}

func TestKafkaProducer_Close_Error(t *testing.T) {
	// Arrange
	mockProducer := new(mocks.KafkaProducerInterface)
	kp := &KafkaProducer{
		producer: mockProducer,
	}

	// Simulate close error
	mockProducer.On("Close").Return()

	// Act
	kp.Close()

	// Assert
	mockProducer.AssertExpectations(t)
}

var kafkaProducerFactory = kafka.NewProducer

type MockKafkaProducer struct {
	mock.Mock
}

func (m *MockKafkaProducer) Produce(msg *kafka.Message, events chan kafka.Event) error {
	args := m.Called(msg, events)
	return args.Error(0)
}

func (m *MockKafkaProducer) Close() {
	m.Called()
}

func mockKafkaNewProducer(conf *kafka.ConfigMap) (*kafka.Producer, error) {
	// Return a mock *kafka.Producer (it doesn't have to be functional)
	mockProducer := new(MockKafkaProducer)
	mockProducer.On("Produce", mock.Anything, mock.Anything).Return(nil)
	mockProducer.On("Close").Return()
	return &kafka.Producer{}, nil
}

func TestGetKafkaProducer_Success(t *testing.T) {

	cfg.BootstrapServer = "localhost:9092"
	cfg.UseSASLForKAFKA = "true"
	kafkaProducerFactory = mockKafkaNewProducer

	_, err := GetKafkaProducer("localhost:9092", "test-topic")

	assert.NoError(t, err)
}

func TestGetKafkaProducer_WithSASL(t *testing.T) {

	// Arrange: Set up the configuration to enable SASL
	cfg.BootstrapServer = "localhost:9092"
	cfg.UseSASLForKAFKA = "true"
	cfg.KAFKA_USERNAME = "test-user"
	cfg.KAFKA_PASSWORD = "test-password"

	_, err := GetKafkaProducer("localhost:9092", "test-topic")

	assert.NoError(t, err)
}

func TestKafkaProducer_Close_NilProducer(t *testing.T) {
	kp := &KafkaProducer{
		producer: nil, // Simulate the nil producer
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)

	kp.Close()

	logOutput := buf.String()
	assert.Contains(t, logOutput, "KafkaProducer or producer is nil, skipping Close.")
}
