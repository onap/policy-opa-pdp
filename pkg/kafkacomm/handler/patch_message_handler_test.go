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
	"policy-opa-pdp/consts"
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

// shortenConsumerBackoff collapses the multi-second Kafka backoff sleeps for the
// duration of a test. ReadKafkaMessages sleeps ConsumerReconnectRetries inside the
// read on ErrAllBrokersDown, so without this the handler cannot reach a second loop
// iteration before any realistic test context expires.
func shortenConsumerBackoff(t *testing.T) {
	oldReconnect, oldPoll := consts.ConsumerReconnectRetries, consts.ConsumerPollSleep
	consts.ConsumerReconnectRetries = time.Millisecond
	consts.ConsumerPollSleep = time.Millisecond
	t.Cleanup(func() {
		consts.ConsumerReconnectRetries = oldReconnect
		consts.ConsumerPollSleep = oldPoll
	})
}

func TestPatchMessageHandler_FatalError_RecoverySuccess(t *testing.T) {
	shortenConsumerBackoff(t)

	oldRecover := recoverConsumerVar
	oldPatch := data.PatchDataVar
	defer func() {
		recoverConsumerVar = oldRecover
		data.PatchDataVar = oldPatch
	}()

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

	// After recovery, ReadMessage returns a valid message
	msgBytes, _ := json.Marshal(model.PatchMessage{
		Header: model.Header{MessageType: model.OPA_PDP_DATA_PATCH_SYNC.String()},
	})
	newMockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(&kafka.Message{Value: msgBytes}, nil)

	recoveryAttempts := 0
	recoverConsumerVar = func(kc *kafkacomm.KafkaConsumer, topic, groupId string) (*kafkacomm.KafkaConsumer, error) {
		recoveryAttempts++
		assert.Same(t, mockKafkaConsumer, kc)
		assert.Equal(t, "patch-topic", topic)
		return newMockKafkaConsumer, nil
	}

	// The timeout is only a backstop: if the handler ever stops routing recovery through
	// recoverConsumerVar, the stub below never runs, nothing cancels the context and the
	// loop would otherwise spin forever building real consumers.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Stop the loop as soon as a message read from the *recovered* consumer has been
	// patched; reaching this proves the new consumer was actually adopted.
	patched := 0
	data.PatchDataVar = func(patchInfos []opasdk.PatchImpl, _ http.ResponseWriter) error {
		patched++
		cancel()
		return nil
	}

	err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
	assert.NoError(t, err)
	assert.Equal(t, 1, recoveryAttempts, "recovery must go through the recoverConsumerVar seam")
	assert.Equal(t, 1, patched, "handler must switch to the recovered consumer")
	mockConsumer.AssertExpectations(t)
}

func TestPatchMessageHandler_RecoveryFailed(t *testing.T) {
	shortenConsumerBackoff(t)

	oldRecover := recoverConsumerVar
	oldPatch := data.PatchDataVar
	defer func() {
		recoverConsumerVar = oldRecover
		data.PatchDataVar = oldPatch
	}()

	mockConsumer := new(MockKafkaConsumer)
	mockConsumer.On("Unsubscribe").Return(nil).Maybe()
	mockConsumer.On("Close").Return(nil).Maybe()
	fatalErr := kafka.NewError(kafka.ErrAllBrokersDown, "brokers down", true)
	mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, fatalErr)

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

	// Timeout is a backstop against the seam being bypassed again — see the sibling test.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Mock recovery to fail. Stop after the second attempt so the test also proves the
	// handler keeps retrying rather than giving up or swapping in the nil consumer.
	recoveryAttempts := 0
	recoverConsumerVar = func(kc *kafkacomm.KafkaConsumer, topic, groupId string) (*kafkacomm.KafkaConsumer, error) {
		recoveryAttempts++
		assert.Same(t, mockKafkaConsumer, kc, "failed recovery must not replace the consumer")
		if recoveryAttempts == 2 {
			cancel()
		}
		return nil, errors.New("recovery failed")
	}

	patched := 0
	data.PatchDataVar = func(patchInfos []opasdk.PatchImpl, _ http.ResponseWriter) error {
		patched++
		return nil
	}

	err := PatchMessageHandler(ctx, mockKafkaConsumer, "patch-topic")
	assert.NoError(t, err)
	assert.Equal(t, 2, recoveryAttempts, "recovery must go through the recoverConsumerVar seam")
	assert.Zero(t, patched, "no message can be processed while recovery keeps failing")
}
