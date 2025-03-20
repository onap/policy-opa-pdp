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

package publisher

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"policy-opa-pdp/pkg/kafkacomm/publisher/mocks"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/policymap"
	"testing"
)

// Mock Policymap
type MockPolicymap struct {
	mock.Mock
}

func (m *MockPolicymap) ExtractDeployedPolicies(policiesMap string) []model.ToscaConceptIdentifier {
	args := m.Called(policiesMap)
	return args.Get(0).([]model.ToscaConceptIdentifier)
}

func (m *MockPolicymap) SetLastDeployedPolicies(policiesMap string) {
	m.Called(policiesMap)
}

// TestSendPdpUpdateResponse_Success tests SendPdpUpdateResponse for a successful response
func TestSendPdpUpdateResponse_Success(t *testing.T) {

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}

	err := SendPdpUpdateResponse(mockSender, pdpUpdate, "PDPUpdate Successful")
	assert.NoError(t, err)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendPdpUpdateResponse_Failure tests SendPdpUpdateResponse when SendPdpStatus fails
func TestSendPdpUpdateResponse_Failure(t *testing.T) {

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("mock send error"))

	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}

	err := SendPdpUpdateResponse(mockSender, pdpUpdate, "PDPUpdate Failure")

	assert.Error(t, err)

	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendPdpUpdateResponse_Success tests SendPdpUpdateResponse for a successful response with no deployed policy
func TestSendPdpUpdateResponse_Success_NoPolicies(t *testing.T) {
	mockPolicymap := new(MockPolicymap)

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}
	policymap.LastDeployedPolicies = ""
	mockPolicymap.On("ExtractDeployedPolicies", mock.Anything).Return(nil)

	err := SendPdpUpdateResponse(mockSender, pdpUpdate, "PDPUpdate Successful")
	assert.NoError(t, err)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendPdpUpdateResponse_Success tests SendPdpUpdateResponse for a successful response with some policies
func TestSendPdpUpdateResponse_Success_SomeDeployedPolicies(t *testing.T) {
	mockPolicymap := new(MockPolicymap)
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}
	policymap.LastDeployedPolicies = "some-policies"
	mockPolicymap.On("ExtractDeployedPolicies", mock.Anything).Return(nil)
	err := SendPdpUpdateResponse(mockSender, pdpUpdate, "PDPUpdate Successful")
	assert.NoError(t, err)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendPdpUpdateErrorResponse_Success tests SendPdpUpdateResponse
func TestSendPdpUpdateErrorResponse(t *testing.T) {

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Sending error response"))

	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}

	mockerr := errors.New("Sending Error response")
	err := SendPdpUpdateErrorResponse(mockSender, pdpUpdate, mockerr)

	assert.Error(t, err)

	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendPdpUpdateErrorResponse_Success tests SendPdpUpdateResponse for some policies
func TestSendPdpUpdateErrorResponse_SomeDeployedPolicies(t *testing.T) {
	// Setup mock Policymap
	mockPolicymap := new(MockPolicymap)

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Sending error response"))
	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}

	policymap.LastDeployedPolicies = "some-policies"
	// Set mock behavior for policymap
	mockPolicymap.On("ExtractDeployedPolicies", mock.Anything).Return(nil)
	mockerr := errors.New("Sending Error response")
	err := SendPdpUpdateErrorResponse(mockSender, pdpUpdate, mockerr)
	assert.Error(t, err)
	//mockPolicymap.AssertExpectations(t)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendPdpUpdateErrorResponse_Success tests SendPdpUpdateResponse for no policies
func TestSendPdpUpdateErrorResponse_NoPolicies(t *testing.T) {
	// Setup mock Policymap
	mockPolicymap := new(MockPolicymap)

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Sending error response"))
	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}

	policymap.LastDeployedPolicies = ""
	// Set mock behavior for policymap
	mockPolicymap.On("ExtractDeployedPolicies", mock.Anything).Return(nil)
	mockerr := errors.New("Sending Error response")
	err := SendPdpUpdateErrorResponse(mockSender, pdpUpdate, mockerr)
	assert.Error(t, err)
	//mockPolicymap.AssertExpectations(t)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendStateChangeResponse_Success tests SendStateChangeResponse for a successful state change response
func TestSendStateChangeResponse_Success(t *testing.T) {

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	pdpStateChange := &model.PdpStateChange{RequestId: "test-state-change-id"}

	err := SendStateChangeResponse(mockSender, pdpStateChange)

	assert.NoError(t, err)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendStateChangeResponse_Failure tests SendStateChangeResponse when SendPdpStatus fails
func TestSendStateChangeResponse_Failure(t *testing.T) {

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("mock send error"))

	pdpStateChange := &model.PdpStateChange{RequestId: "test-state-change-id"}

	err := SendStateChangeResponse(mockSender, pdpStateChange)
	assert.Error(t, err)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)

}
