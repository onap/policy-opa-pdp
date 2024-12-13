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
//

package kafkacomm

import (
	"errors"
	"testing"
	"time"
	//	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

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

		// Mock Produce method to simulate successful delivery
		mockProducer.On("Produce", mock.Anything, mock.Anything).Return(nil)

		// Act
		err := kp.Produce(message)

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

	// Act
	err := kp.Produce([]byte("test message"))

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
