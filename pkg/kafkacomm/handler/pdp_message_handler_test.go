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
//

package handler

import (
	"context"
	"errors"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/kafkacomm/mocks"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/pdpattributes"
	"testing"
	"time"
)

type KafkaConsumerInterface interface {
	ReadMessage(time.Duration) ([]byte, error)
	ReadKafkaMessages() ([]byte, error)
}

type MockKafkaConsumer struct {
	mock.Mock
}

func (m *MockKafkaConsumer) Unsubscribe() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockKafkaConsumer) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockKafkaConsumer) ReadMessage(timeout time.Duration) (*kafka.Message, error) {
	args := m.Called(timeout)
	msg := args.Get(0)
	if msg == nil {
		return nil, args.Error(1)
	}
	return msg.(*kafka.Message), args.Error(1)
}

func (m *MockKafkaConsumer) ReadKafkaMessages(kc *kafkacomm.KafkaConsumer) ([]byte, error) {
	args := m.Called(kc)
	return args.Get(0).([]byte), args.Error(0)
}

/*
checkIfMessageIsForOpaPdp_Check
Description: Validating Message Attributes
Input: PDP message
Expected Output: Returning true stating all the values are validated successfully
*/
func TestCheckIfMessageIsForOpaPdp_Check(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = "opa-3a318049-813f-4172-b4d3-7d4f466e5b80"
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "opa"

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Its a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_Message_Name
Description: Validating Message Attributes
Input: PDP message with name as empty
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_Message_Name(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "opa"

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Not a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_PdpGroup
Description: Validating Message Attributes
Input: PDP message with invalid PdpGroup
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_PdpGroup(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "opa"

	pdpattributes.SetPdpSubgroup("opa")
	assert.True(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Its a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_EmptyPdpGroup
Description: Validating Message Attributes
Input: PDP Group Empty
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_EmptyPdpGroup(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = ""
	opapdpMessage.PdpSubgroup = "opa"

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Not a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_PdpSubgroup
Description: Validating Message Attributes
Input: PDP message with invalid PdpSubgroup
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_PdpSubgroup(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "opa"

	pdpattributes.SetPdpSubgroup("opa")
	assert.True(t, checkIfMessageIsForOpaPdp(opapdpMessage), "It's a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_IncorrectPdpSubgroup
Description: Validating Message Attributes
Input: PDP message with empty  PdpSubgroup
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_IncorrectPdpSubgroup(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "o"

	pdpattributes.SetPdpSubgroup("opa")
	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Not a valid Opa Pdp Message")

}

func TestCheckIfMessageIsForOpaPdp_EmptyPdpSubgroupAndGroup(t *testing.T) {
	var opapdpMessage OpaPdpMessage
	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = ""
	opapdpMessage.PdpSubgroup = ""

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Message should be invalid when PdpGroup and PdpSubgroup are empty")
}

func TestCheckIfMessageIsForOpaPdp_ValidBroadcastMessage(t *testing.T) {
	var opapdpMessage OpaPdpMessage
	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_UPDATE"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = ""

	pdpattributes.SetPdpSubgroup("opa")
	consts.PdpGroup = "opaGroup"

	assert.True(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Valid broadcast message should pass the check")
}

func TestCheckIfMessageIsForOpaPdp_InvalidGroupMismatch(t *testing.T) {
	var opapdpMessage OpaPdpMessage
	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "wrongGroup"
	opapdpMessage.PdpSubgroup = ""

	consts.PdpGroup = "opaGroup"

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Message with mismatched PdpGroup should fail")
}

// Test SetShutdownFlag and IsShutdown
func TestSetAndCheckShutdownFlag(t *testing.T) {
	assert.False(t, IsShutdown(), "Shutdown flag should be false initially")

	SetShutdownFlag()
	assert.True(t, IsShutdown(), "Shutdown flag should be true after calling SetShutdownFlag")
}

func TestPdpMessageHandler_ValidPDPUpdate(t *testing.T) {
	t.Run("Process PDP_UPDATE Message", func(t *testing.T) {
		message := `{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_UPDATE",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	         }`

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel() // cancel is called to release resources

		mockConsumer := new(mocks.KafkaConsumerInterface)
		mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
		mockConsumer.On("Close", mock.Anything).Return(nil, nil)
		expectedError := error(nil)

		// Create a kafka.Message
		kafkaMsg := &kafka.Message{
			Value: []byte(message),
		}
		mockConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)

		mockKafkaConsumer := &kafkacomm.KafkaConsumer{
			Consumer: mockConsumer,
		}

		mockPublisher := new(MockPdpStatusSender)

		mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(nil)

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error processing PDP_UPDATE message")

	})
}

func TestPdpMessageHandler_ValidPdpStateChange(t *testing.T) {
	t.Run("Process PDP STATE CHANGE Message Handler", func(t *testing.T) {
		message := `{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName": "PDP_STATE_CHANGE",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	         }`

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		mockConsumer := new(mocks.KafkaConsumerInterface)
		mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
		mockConsumer.On("Close", mock.Anything).Return(nil, nil)
		expectedError := error(nil)

		// Create a kafka.Message
		kafkaMsg := &kafka.Message{
			Value: []byte(message),
		}
		mockConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)

		mockKafkaConsumer := &kafkacomm.KafkaConsumer{
			Consumer: mockConsumer,
		}

		mockPublisher := new(MockPdpStatusSender)

		mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(nil)

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error processing PDP STATE CHANGE message")

	})
}

func TestPdpMessageHandler_DiscardPdpStatus(t *testing.T) {
	t.Run("Process PDP STATUS Message Handler", func(t *testing.T) {
		message := `{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_STATUS",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	         }`

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		mockConsumer := new(mocks.KafkaConsumerInterface)
		mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
		mockConsumer.On("Close", mock.Anything).Return(nil, nil)
		expectedError := error(nil)

		// Create a kafka.Message
		kafkaMsg := &kafka.Message{
			Value: []byte(message),
		}
		mockConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)

		mockKafkaConsumer := &kafkacomm.KafkaConsumer{
			Consumer: mockConsumer,
		}

		mockPublisher := new(MockPdpStatusSender)

		mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(nil)

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error processing PDP_UPDATE message")

	})
}

func TestPdpMessageHandler_InvalidMessage(t *testing.T) {
	t.Run("Process Invalid PDP Message Handler", func(t *testing.T) {
		message := `{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_INVALID",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"",
	        "pdpGroup":"opaGroup",
	                        "pdpSubgroup":"opa"
	         }`

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		mockConsumer := new(mocks.KafkaConsumerInterface)
		mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
		mockConsumer.On("Close", mock.Anything).Return(nil, nil)
		expectedError := error(nil)

		// Create a kafka.Message
		kafkaMsg := &kafka.Message{
			Value: []byte(message),
		}
		mockConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)

		mockKafkaConsumer := &kafkacomm.KafkaConsumer{
			Consumer: mockConsumer,
		}

		mockPublisher := new(MockPdpStatusSender)

		mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(nil)

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error processing INVALID PDP message")

	})
}

func TestPdpMessageHandler_ContextCancelled(t *testing.T) {
	t.Run("Context is canceled", func(t *testing.T) {
		message := `{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_INVALID",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	         }`
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Immediately cancel the context

		mockConsumer := new(mocks.KafkaConsumerInterface)
		mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
		mockConsumer.On("Close", mock.Anything).Return(nil, nil)
		expectedError := error(nil)

		// Create a kafka.Message
		kafkaMsg := &kafka.Message{
			Value: []byte(message),
		}
		mockConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)

		mockKafkaConsumer := &kafkacomm.KafkaConsumer{
			Consumer: mockConsumer,
		}

		mockPublisher := new(MockPdpStatusSender)

		mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(nil)

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error while testing context cancelled")

	})
}

func TestPdpMessageHandler_InvalidOPAPdpmessage(t *testing.T) {
	t.Run("Invalid OPA PDP message", func(t *testing.T) {
		message := `{
	        "":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_UPDATE",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	         }`
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel() // cancel is called to release resources

		mockConsumer := new(mocks.KafkaConsumerInterface)
		mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
		mockConsumer.On("Close", mock.Anything).Return(nil, nil)
		expectedError := error(nil)

		// Create a kafka.Message
		kafkaMsg := &kafka.Message{
			Value: []byte(message),
		}
		mockConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)

		mockKafkaConsumer := &kafkacomm.KafkaConsumer{
			Consumer: mockConsumer,
		}

		mockPublisher := new(MockPdpStatusSender)
		mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(errors.New("Jsonunmarshal Error"))

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error processing PDP_UPDATE message")

	})
}

func TestPdpMessageHandler_InvalidOPAPdpStateChangemessage(t *testing.T) {
	t.Run("Invalid OPA PDP State Change message", func(t *testing.T) {
		message := `{
	        "sourc":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_STATE_CHANGE",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	         }`
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		mockConsumer := new(mocks.KafkaConsumerInterface)
		mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
		mockConsumer.On("Close", mock.Anything).Return(nil, nil)
		expectedError := error(nil)

		// Create a kafka.Message
		kafkaMsg := &kafka.Message{
			Value: []byte(message),
		}
		mockConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)

		mockKafkaConsumer := &kafkacomm.KafkaConsumer{
			Consumer: mockConsumer,
		}

		mockPublisher := new(MockPdpStatusSender)
		mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(errors.New("Jsonunmarshal Error"))

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error processing Invalid OPA PDP STATE CHANGE message")

	})
}

func TestPdpMessageHandler_jsonunmarshallOPAPdpStateChangemessage(t *testing.T) {
	t.Run("Invalid OPA PDP State Change message", func(t *testing.T) {
		message := `{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_STATE_CHANGE"
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	         }`
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		mockConsumer := new(mocks.KafkaConsumerInterface)
		mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
		mockConsumer.On("Close", mock.Anything).Return(nil, nil)
		expectedError := error(nil)

		// Create a kafka.Message
		kafkaMsg := &kafka.Message{
			Value: []byte(message),
		}
		mockConsumer.On("ReadMessage", mock.Anything).Return(kafkaMsg, expectedError)

		mockKafkaConsumer := &kafkacomm.KafkaConsumer{
			Consumer: mockConsumer,
		}

		mockPublisher := new(MockPdpStatusSender)
		mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(errors.New("Jsonunmarshal Error"))

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error processing Invalid OPA PDP State Change message")

	})
}

func TestHandlePdpMessageTypes_Update(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	pdpUpdateMessageHandlerVar = func(ctx context.Context, msg []byte, p publisher.PdpStatusSender) error {
		assert.Equal(t, "update-message", string(msg))
		return nil
	}

	handlePdpMessageTypes(context.Background(), "PDP_UPDATE", []byte("update-message"), mockSender)
	// Add assertions on log output if needed
}

func TestHandlePdpMessageTypes_Update_Error(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	pdpUpdateMessageHandlerVar = func(ctx context.Context, msg []byte, p publisher.PdpStatusSender) error {
		return errors.New("mock update error")
	}

	handlePdpMessageTypes(context.Background(), "PDP_UPDATE", []byte("bad-message"), mockSender)
}

func TestHandlePdpMessageTypes_StateChange(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	pdpStateChangeMessageHandlerVar = func(ctx context.Context, msg []byte, p publisher.PdpStatusSender) error {
		assert.Equal(t, "state-change", string(msg))
		return nil
	}

	handlePdpMessageTypes(context.Background(), "PDP_STATE_CHANGE", []byte("state-change"), mockSender)
}

func TestHandlePdpMessageTypes_StateChange_Error(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	pdpStateChangeMessageHandlerVar = func(ctx context.Context, msg []byte, p publisher.PdpStatusSender) error {
		return errors.New("mock state change error")
	}

	handlePdpMessageTypes(context.Background(), "PDP_STATE_CHANGE", []byte("bad-state"), mockSender)
}

func TestHandlePdpMessageTypes_Status(t *testing.T) {
	mockSender := new(MockPdpStatusSender)
	handlePdpMessageTypes(context.Background(), "PDP_STATUS", []byte("ignore"), mockSender)
}

func TestHandlePdpMessageTypes_Invalid(t *testing.T) {
	mockSender := new(MockPdpStatusSender)
	handlePdpMessageTypes(context.Background(), "INVALID_TYPE", []byte("invalid"), mockSender)
}

func TestShouldRebuildConsumer(t *testing.T) {
	assert.False(t, shouldRebuildConsumer(nil))

	fatalErr := kafka.NewError(kafka.ErrAllBrokersDown, "brokers down", true)
	assert.True(t, shouldRebuildConsumer(fatalErr))

	authErr := kafka.NewError(kafka.ErrAuthentication, "auth failed", false)
	assert.True(t, shouldRebuildConsumer(authErr))

	nonFatalErr := kafka.NewError(kafka.ErrUnknownTopicOrPart, "unknown topic", false)
	assert.False(t, shouldRebuildConsumer(nonFatalErr))

	stringErr1 := errors.New("something AUTH related")
	assert.True(t, shouldRebuildConsumer(stringErr1))

	stringErr2 := errors.New("BROKERS_DOWN error")
	assert.True(t, shouldRebuildConsumer(stringErr2))

	stringErr3 := errors.New("random error")
	assert.False(t, shouldRebuildConsumer(stringErr3))
}

func TestConsumerNonFatalBackoff(t *testing.T) {
	// Pin the duration this asserts on instead of paying the production one.
	old := consts.ConsumerTearDownSleepTime
	consts.ConsumerTearDownSleepTime = 20 * time.Millisecond
	t.Cleanup(func() { consts.ConsumerTearDownSleepTime = old })

	start := time.Now()
	consumerNonFatalBackoff()

	assert.GreaterOrEqual(t, time.Since(start), consts.ConsumerTearDownSleepTime)
}

func TestPdpMessageHandler_FatalError_RecoverySuccess(t *testing.T) {
	shortenConsumerBackoff(t)

	oldRecover := recoverConsumerVar
	defer func() { recoverConsumerVar = oldRecover }()

	mockConsumer := new(mocks.KafkaConsumerInterface)
	// Return a fatal error
	fatalErr := kafka.NewError(kafka.ErrAllBrokersDown, "brokers down", true)
	mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
	mockConsumer.On("Close", mock.Anything).Return(nil, nil)
	mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, fatalErr).Once()

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

	// Mock recovery to return a new consumer
	newMockConsumer := new(mocks.KafkaConsumerInterface)
	newMockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: newMockConsumer}
	newMockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
	newMockConsumer.On("Close", mock.Anything).Return(nil, nil)

	// After recovery, next ReadMessage returns a valid message to break the loop
	message := `{
            "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
            "pdpHeartbeatIntervalMs":120000,
            "policiesToBeDeployed":[],
            "policiesToBeUndeployed":[],
            "messageName":"PDP_UPDATE",
            "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
            "timestampMs":1730722305297,
            "name":"",
            "pdpGroup":"opaGroup",
            "pdpSubgroup":"opa"
             }`
	kafkaMsg := &kafka.Message{Value: []byte(message)}
	newMockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(kafkaMsg, nil)

	recoveryAttempts := 0
	recoverConsumerVar = func(kc *kafkacomm.KafkaConsumer, topic, groupId string) (*kafkacomm.KafkaConsumer, error) {
		recoveryAttempts++
		return newMockKafkaConsumer, nil
	}

	// Backstop only; the handler is stopped by cancel() below once it has processed a
	// message read from the recovered consumer.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockPublisher := new(MockPdpStatusSender)
	mockPublisher.On("SendPdpStatus", mock.Anything, mock.Anything).Return(nil)

	oldUpdate := pdpUpdateMessageHandlerVar
	defer func() { pdpUpdateMessageHandlerVar = oldUpdate }()
	handled := 0
	pdpUpdateMessageHandlerVar = func(ctx context.Context, msg []byte, p publisher.PdpStatusSender) error {
		handled++
		cancel()
		return nil
	}

	err := PdpMessageHandler(ctx, mockKafkaConsumer, "pdp-topic", mockPublisher)
	assert.NoError(t, err)
	assert.Equal(t, 1, recoveryAttempts)
	assert.Equal(t, 1, handled, "handler must switch to the recovered consumer")
}

func TestPdpMessageHandler_RecoveryFailed(t *testing.T) {
	shortenConsumerBackoff(t)

	oldRecover := recoverConsumerVar
	defer func() { recoverConsumerVar = oldRecover }()

	mockConsumer := new(mocks.KafkaConsumerInterface)
	fatalErr := kafka.NewError(kafka.ErrAllBrokersDown, "brokers down", true)
	mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, fatalErr)

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

	// Backstop only; the handler is stopped from the stub below.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Mock recovery to fail. Stop after the second attempt, which also proves the handler
	// keeps retrying rather than giving up or adopting the nil consumer.
	recoveryAttempts := 0
	recoverConsumerVar = func(kc *kafkacomm.KafkaConsumer, topic, groupId string) (*kafkacomm.KafkaConsumer, error) {
		recoveryAttempts++
		assert.Same(t, mockKafkaConsumer, kc, "failed recovery must not replace the consumer")
		if recoveryAttempts == 2 {
			cancel()
		}
		return nil, errors.New("recovery failed")
	}

	mockPublisher := new(MockPdpStatusSender)
	err := PdpMessageHandler(ctx, mockKafkaConsumer, "pdp-topic", mockPublisher)
	assert.NoError(t, err)
	assert.Equal(t, 2, recoveryAttempts)
}

func TestPdpMessageHandler_NonFatalError(t *testing.T) {
	shortenConsumerBackoff(t)

	nonFatalErr := errors.New("transient error")

	mockConsumer := new(mocks.KafkaConsumerInterface)
	mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, nonFatalErr)

	mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	mockPublisher := new(MockPdpStatusSender)
	err := PdpMessageHandler(ctx, mockKafkaConsumer, "pdp-topic", mockPublisher)
	assert.NoError(t, err)
}

func TestRecoverConsumer(t *testing.T) {
	shortenConsumerBackoff(t)

	mockConsumer := new(mocks.KafkaConsumerInterface)
	mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
	mockConsumer.On("Close", mock.Anything).Return(nil, nil)
	kc := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

	// This will test the recoverConsumer directly.
	newKc, err := recoverConsumer(kc, "test-topic", "test-group")

	// Verify that Teardown methods were called
	mockConsumer.AssertExpectations(t)

	// The replacement consumer is built by librdkafka, so only its success/failure
	// contract can be asserted here, not a connection.
	if err == nil {
		assert.NotNil(t, newKc)
	} else {
		assert.Nil(t, newKc)
	}
}

// newRecordingProvider installs a provider that keeps every span in memory, so a
// test can assert on the trace the handler produced.
func newRecordingProvider(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()

	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	recorder := tracetest.NewSpanRecorder()

	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)))
	otel.SetTextMapPropagator(propagation.TraceContext{})

	t.Cleanup(func() {
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})

	return recorder
}

func TestDispatchInSpan_ContinuesPapTrace(t *testing.T) {
	recorder := newRecordingProvider(t)

	previousHandler := pdpUpdateMessageHandlerVar
	pdpUpdateMessageHandlerVar = func(ctx context.Context, message []byte, p publisher.PdpStatusSender) error {
		return nil
	}
	t.Cleanup(func() { pdpUpdateMessageHandlerVar = previousHandler })

	msg := &kafka.Message{
		Value: []byte(`{"messageName":"PDP_UPDATE"}`),
		Headers: []kafka.Header{{
			Key:   "traceparent",
			Value: []byte("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
		}},
	}

	dispatchInSpan(context.Background(), "policy-pdp-pap", msg,
		OpaPdpMessage{MessageType: "PDP_UPDATE"}, new(MockPdpStatusSender))

	spans := recorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "consume policy-pdp-pap", spans[0].Name())
	assert.Equal(t, trace.SpanKindConsumer, spans[0].SpanKind())
	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", spans[0].SpanContext().TraceID().String())
	assert.Equal(t, "b7ad6b7169203331", spans[0].Parent().SpanID().String())
	assert.Contains(t, spans[0].Attributes(),
		attribute.String(messageTypeAttribute, "PDP_UPDATE"))
}

func TestDispatchInSpan_WithoutTraceparentStartsNewTrace(t *testing.T) {
	recorder := newRecordingProvider(t)

	previousHandler := pdpStateChangeMessageHandlerVar
	pdpStateChangeMessageHandlerVar = func(ctx context.Context, message []byte, p publisher.PdpStatusSender) error {
		return nil
	}
	t.Cleanup(func() { pdpStateChangeMessageHandlerVar = previousHandler })

	msg := &kafka.Message{Value: []byte(`{"messageName":"PDP_STATE_CHANGE"}`)}

	dispatchInSpan(context.Background(), "policy-pdp-pap", msg,
		OpaPdpMessage{MessageType: "PDP_STATE_CHANGE"}, new(MockPdpStatusSender))

	spans := recorder.Ended()
	require.Len(t, spans, 1)
	assert.True(t, spans[0].SpanContext().IsValid())
	assert.False(t, spans[0].Parent().IsValid())
}

// The handler must hand its span's context to the message-type handler, otherwise
// the PDP_STATUS response it publishes would start an unrelated trace.
func TestDispatchInSpan_PassesSpanContextToHandler(t *testing.T) {
	recorder := newRecordingProvider(t)

	var handlerTraceID string
	previousHandler := pdpUpdateMessageHandlerVar
	pdpUpdateMessageHandlerVar = func(ctx context.Context, message []byte, p publisher.PdpStatusSender) error {
		handlerTraceID = trace.SpanContextFromContext(ctx).TraceID().String()
		return nil
	}
	t.Cleanup(func() { pdpUpdateMessageHandlerVar = previousHandler })

	msg := &kafka.Message{Value: []byte(`{"messageName":"PDP_UPDATE"}`)}

	dispatchInSpan(context.Background(), "policy-pdp-pap", msg,
		OpaPdpMessage{MessageType: "PDP_UPDATE"}, new(MockPdpStatusSender))

	spans := recorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, spans[0].SpanContext().TraceID().String(), handlerTraceID)
}
