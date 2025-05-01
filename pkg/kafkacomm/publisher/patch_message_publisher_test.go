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
	"errors"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"policy-opa-pdp/pkg/opasdk"
	"testing"
)

// --- Sample PatchImpl for testing ---
func samplePatchData() []opasdk.PatchImpl {
	return []opasdk.PatchImpl{
		{
			Path:  storage.MustParsePath("/policy/config/name"),
			Op:    storage.ReplaceOp,
			Value: "NewPolicyName",
		},
	}
}

// --- Helper to get mock sender ---
func getMockSender() (*RealPatchSender, *MockKafkaProducer) {
	mockProducer := new(MockKafkaProducer)
	sender := &RealPatchSender{
		Producer: mockProducer,
	}
	return sender, mockProducer
}

// --- Test: Successful message send ---
func TestSendPatchMessage_Success(t *testing.T) {
	sender, mockProducer := getMockSender()

	mockProducer.On("Produce", mock.Anything).Return(nil)

	err := sender.SendPatchMessage(samplePatchData())
	assert.NoError(t, err)
	mockProducer.AssertExpectations(t)
}

// --- Test: Kafka produce failure ---
func TestSendPatchMessage_ProduceError(t *testing.T) {
	sender, mockProducer := getMockSender()

	mockProducer.On("Produce", mock.Anything).Return(errors.New("kafka error"))

	err := sender.SendPatchMessage(samplePatchData())
	assert.Error(t, err)
	assert.EqualError(t, err, "kafka error")
	mockProducer.AssertExpectations(t)
}

// --- Test: JSON marshal error ---
func TestSendPatchMessage_MarshalError(t *testing.T) {
	sender, _ := getMockSender()

	badData := []opasdk.PatchImpl{
		{
			Path:  storage.MustParsePath("/invalid"),
			Op:    storage.AddOp,
			Value: make(chan int), // JSON marshal fails on channels
		},
	}

	err := sender.SendPatchMessage(badData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "json: unsupported type: chan int")
}

// --- Test: Validate payload content ---
func TestSendPatchMessage_PayloadContent(t *testing.T) {
	sender, mockProducer := getMockSender()

	mockProducer.On("Produce", mock.MatchedBy(func(msg *kafka.Message) bool {
		var payload PatchKafkaPayload
		err := json.Unmarshal(msg.Value, &payload)
		return err == nil &&
			len(payload.PatchInfos) == 1 &&
			payload.PatchInfos[0].Path.String() == "/policy/config/name" &&
			payload.PatchInfos[0].Value == "NewPolicyName"
	})).Return(nil)

	err := sender.SendPatchMessage(samplePatchData())
	assert.NoError(t, err)
	mockProducer.AssertExpectations(t)
}
