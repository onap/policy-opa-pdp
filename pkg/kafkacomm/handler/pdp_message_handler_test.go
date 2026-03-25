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

func (m *MockKafkaConsumer) pdpUpdateMessageHandler(msg string) error {
	args := m.Called(msg)
	return args.Error(0)
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

	pdpattributes.PdpSubgroup = "opa"
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

	pdpattributes.PdpSubgroup = "opa"
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

	pdpattributes.PdpSubgroup = "opa"
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

	pdpattributes.PdpSubgroup = "opa"
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

		mockPublisher.On("SendPdpStatus", mock.Anything).Return(nil)

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

		mockPublisher.On("SendPdpStatus", mock.Anything).Return(nil)

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

		mockPublisher.On("SendPdpStatus", mock.Anything).Return(nil)

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

		mockPublisher.On("SendPdpStatus", mock.Anything).Return(nil)

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

		mockPublisher.On("SendPdpStatus", mock.Anything).Return(nil)

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
		mockPublisher.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

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
		mockPublisher.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

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
		mockPublisher.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

		err := PdpMessageHandler(ctx, mockKafkaConsumer, "test-topic", mockPublisher)

		assert.NoError(t, err)
		assert.Nil(t, err, "Expected no error processing Invalid OPA PDP State Change message")

	})
}

func TestHandlePdpMessageTypes_Update(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	pdpUpdateMessageHandlerVar = func(msg []byte, p publisher.PdpStatusSender) error {
		assert.Equal(t, "update-message", string(msg))
		return nil
	}

	handlePdpMessageTypes("PDP_UPDATE", []byte("update-message"), mockSender)
	// Add assertions on log output if needed
}

func TestHandlePdpMessageTypes_Update_Error(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	pdpUpdateMessageHandlerVar = func(msg []byte, p publisher.PdpStatusSender) error {
		return errors.New("mock update error")
	}

	handlePdpMessageTypes("PDP_UPDATE", []byte("bad-message"), mockSender)
}

func TestHandlePdpMessageTypes_StateChange(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	pdpStateChangeMessageHandlerVar = func(msg []byte, p publisher.PdpStatusSender) error {
		assert.Equal(t, "state-change", string(msg))
		return nil
	}

	handlePdpMessageTypes("PDP_STATE_CHANGE", []byte("state-change"), mockSender)
}

func TestHandlePdpMessageTypes_StateChange_Error(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	pdpStateChangeMessageHandlerVar = func(msg []byte, p publisher.PdpStatusSender) error {
		return errors.New("mock state change error")
	}

	handlePdpMessageTypes("PDP_STATE_CHANGE", []byte("bad-state"), mockSender)
}

func TestHandlePdpMessageTypes_Status(t *testing.T) {
	mockSender := new(MockPdpStatusSender)
	handlePdpMessageTypes("PDP_STATUS", []byte("ignore"), mockSender)
}

func TestHandlePdpMessageTypes_Invalid(t *testing.T) {
	mockSender := new(MockPdpStatusSender)
	handlePdpMessageTypes("INVALID_TYPE", []byte("invalid"), mockSender)
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
        start := time.Now()
        consumerNonFatalBackoff()
        duration := time.Since(start)
        assert.True(t, duration >= 200*time.Millisecond)
}

func TestPdpMessageHandler_FatalError_RecoverySuccess(t *testing.T) {
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
        newMockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(kafkaMsg, nil).Once()

        recoverConsumerVar = func(kc *kafkacomm.KafkaConsumer, topic, groupId string) (*kafkacomm.KafkaConsumer, error) {
                return newMockKafkaConsumer, nil
        }

        ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
        defer cancel()

        mockPublisher := new(MockPdpStatusSender)
        mockPublisher.On("SendPdpStatus", mock.Anything).Return(nil)

        err := PdpMessageHandler(ctx, mockKafkaConsumer, "pdp-topic", mockPublisher)
        assert.NoError(t, err)
}

func TestPdpMessageHandler_RecoveryFailed(t *testing.T) {
        oldRecover := recoverConsumerVar
        defer func() { recoverConsumerVar = oldRecover }()

        mockConsumer := new(mocks.KafkaConsumerInterface)
        fatalErr := kafka.NewError(kafka.ErrAllBrokersDown, "brokers down", true)
        mockConsumer.On("ReadMessage", mock.AnythingOfType("time.Duration")).Return(nil, fatalErr).Once()

        mockKafkaConsumer := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        // Mock recovery to fail
        recoverConsumerVar = func(kc *kafkacomm.KafkaConsumer, topic, groupId string) (*kafkacomm.KafkaConsumer, error) {
                return nil, errors.New("recovery failed")
        }

        ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
        defer cancel()

        mockPublisher := new(MockPdpStatusSender)
        err := PdpMessageHandler(ctx, mockKafkaConsumer, "pdp-topic", mockPublisher)
        assert.NoError(t, err)
}

func TestPdpMessageHandler_NonFatalError(t *testing.T) {
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
        mockConsumer := new(mocks.KafkaConsumerInterface)
        mockConsumer.On("Unsubscribe", mock.Anything).Return(nil, nil)
        mockConsumer.On("Close", mock.Anything).Return(nil, nil)
        kc := &kafkacomm.KafkaConsumer{Consumer: mockConsumer}

        // This will test the recoverConsumer directly.
        newKc, err := recoverConsumer(kc, "test-topic", "test-group")

        // Verify that Teardown methods were called
        mockConsumer.AssertExpectations(t)

        // Suppress unused variable warnings
        _ = newKc
        _ = err
}
