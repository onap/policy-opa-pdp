// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2025-2026: Deutsche Telekom
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
	"policy-opa-pdp/pkg/model"
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

	msgBytes, _ := json.Marshal(model.PatchMessage{PatchInfos: samplePatchData()})

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

	msgBytes, _ := json.Marshal(model.PatchMessage{PatchInfos: samplePatchData()})

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

func TestPatchMessageHandler_NilMessage(t *testing.T) {
        mockConsumer := new(MockKafkaConsumer)
        // Return ErrTimedOut which is correctly handled by ReadKafkaMessages
        timeoutErr := kafka.NewError(kafka.ErrTimedOut, "timeout", false)
        mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, timeoutErr)

        mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
        defer cancel()

        err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
        assert.NoError(t, err)
        mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_InvalidMessageType(t *testing.T) {
        patchMsg := model.PatchMessage{
                Header: model.Header{
                        MessageType: "INVALID_TYPE",
                },
        }
        msgBytes, _ := json.Marshal(patchMsg)
        mockKafkaMessage := &kafka.Message{Value: msgBytes}

        mockConsumer := new(MockKafkaConsumer)
        mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(mockKafkaMessage, nil)

        mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
        defer cancel()

        err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
        assert.NoError(t, err)
        mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_EmptyMessageType(t *testing.T) {
        patchMsg := model.PatchMessage{
                Header: model.Header{
                        MessageType: "",
                },
        }
        msgBytes, _ := json.Marshal(patchMsg)
        mockKafkaMessage := &kafka.Message{Value: msgBytes}

        mockConsumer := new(MockKafkaConsumer)
        mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(mockKafkaMessage, nil)

        mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
        defer cancel()

        err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
        assert.NoError(t, err)
        mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_NonFatalError(t *testing.T) {
        // A non-fatal error is any error that is NOT a kafka.Error or a kafka.Error that is not fatal
        nonFatalErr := errors.New("transient error")

        mockConsumer := new(MockKafkaConsumer)
        mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, nonFatalErr)

        mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
        defer cancel()

        err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
        assert.NoError(t, err)
        mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_ValidMessage_WithHeader(t *testing.T) {
        defer func() { data.PatchDataVar = originalPatchDataVar }()
        data.PatchDataVar = func(patchInfos []opasdk.PatchImpl, _ http.ResponseWriter) error { return nil }

        patchMsg := model.PatchMessage{
                Header: model.Header{
                        MessageType: model.OPA_PDP_DATA_PATCH_SYNC.String(),
                        SourceID:    "test-source",
                },
                PatchInfos: samplePatchData(),
        }
        msgBytes, _ := json.Marshal(patchMsg)
        mockKafkaMessage := &kafka.Message{Value: msgBytes}

        mockConsumer := new(MockKafkaConsumer)
        mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(mockKafkaMessage, nil)

        mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
        defer cancel()

        err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
        assert.NoError(t, err)
        mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_FatalError_RecoverySuccess(t *testing.T) {
        oldRecover := recoverConsumerVar
        defer func() { recoverConsumerVar = oldRecover }()

        mockConsumer := new(MockKafkaConsumer)
	mockConsumer.On("Unsubscribe").Return(nil).Maybe()
	mockConsumer.On("Close").Return(nil).Maybe()
        // Return a fatal error
        fatalErr := kafka.NewError(kafka.ErrAllBrokersDown, "brokers down", true)
        mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, fatalErr).Once()

        mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        // Mock recovery to return a new consumer
        newMockConsumer := new(MockKafkaConsumer)
	newMockConsumer.On("Unsubscribe").Return(nil).Maybe()
	newMockConsumer.On("Close").Return(nil).Maybe()
        newMockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: newMockConsumer}

        // After recovery, next ReadMessage returns a valid message to break the loop
        msgBytes, _ := json.Marshal(model.PatchMessage{
                Header: model.Header{MessageType: model.OPA_PDP_DATA_PATCH_SYNC.String()},
        })
        newMockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(&kafka.Message{Value: msgBytes}, nil).Once()

        recoverConsumerVar = func(kc *kafkacomm.KafkaConsumer, topic, groupId string) (*kafkacomm.KafkaConsumer, error) {
                return newMockKafkaConsumer, nil
        }

        ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
        defer cancel()

        err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
        assert.NoError(t, err)
}

func TestPatchMessageHandler_RecoveryFailed(t *testing.T) {
        oldRecover := recoverConsumerVar
        defer func() { recoverConsumerVar = oldRecover }()

        mockConsumer := new(MockKafkaConsumer)
	mockConsumer.On("Unsubscribe").Return(nil).Maybe()
	mockConsumer.On("Close").Return(nil).Maybe()
        fatalErr := kafka.NewError(kafka.ErrAllBrokersDown, "brokers down", true)
        mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, fatalErr).Once()

        mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        // Mock recovery to fail
        recoverConsumerVar = func(kc *kafkacomm.KafkaConsumer, topic, groupId string) (*kafkacomm.KafkaConsumer, error) {
                return nil, errors.New("recovery failed")
        }

        ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
        defer cancel()

        err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
        assert.NoError(t, err)
}
