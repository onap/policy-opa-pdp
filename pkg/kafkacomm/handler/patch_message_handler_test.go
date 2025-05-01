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

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net/http"
	"policy-opa-pdp/pkg/data"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/opasdk"
	"testing"
	"time"
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

var originalPatchDataVar = data.PatchDataVar

func TestPatchMessageHandler_Success(t *testing.T) {
	defer func() { data.PatchDataVar = originalPatchDataVar }()

	// Mock PatchDataVar to simulate success
	data.PatchDataVar = func(patchInfos []opasdk.PatchImpl, _ http.ResponseWriter) error {
		return nil
	}

	msgBytes, _ := json.Marshal(PatchMessage{PatchInfos: samplePatchData()})

	mockKafkaMessage := &kafka.Message{
		Value: []byte(msgBytes),
	}
	mockConsumer := new(MockKafkaConsumer)
	mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(mockKafkaMessage, nil)

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{
		Consumer: mockConsumer,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
	assert.NoError(t, err)
	mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_PatchFail(t *testing.T) {
	defer func() { data.PatchDataVar = originalPatchDataVar }()

	data.PatchDataVar = func(patchInfos []opasdk.PatchImpl, _ http.ResponseWriter) error {
		return errors.New("mock failure")
	}

	msgBytes, _ := json.Marshal(PatchMessage{PatchInfos: samplePatchData()})

	mockKafkaMessage := &kafka.Message{
		Value: []byte(msgBytes),
	}

	mockConsumer := new(MockKafkaConsumer)
	mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(mockKafkaMessage, nil)

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{
		Consumer: mockConsumer,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
	assert.NoError(t, err)
	mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_ReadError(t *testing.T) {
	defer func() { data.PatchDataVar = originalPatchDataVar }()

	mockConsumer := new(MockKafkaConsumer)
	mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).
		Return(nil, errors.New("read error"))

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
	assert.NoError(t, err)
	mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_UnmarshalFail(t *testing.T) {
	defer func() { data.PatchDataVar = originalPatchDataVar }()

	invalidJSON := []byte(`invalid json`)
	mockKafkaMessage := &kafka.Message{Value: invalidJSON}

	mockConsumer := new(MockKafkaConsumer)
	mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(mockKafkaMessage, nil)

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
	assert.NoError(t, err)
	mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_ContextDone(t *testing.T) {
	mockConsumer := new(MockKafkaConsumer)
	mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

	// Context is cancelled immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
	assert.NoError(t, err)
}
