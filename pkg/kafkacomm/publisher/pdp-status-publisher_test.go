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

package publisher

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"policy-opa-pdp/pkg/kafkacomm/publisher/mocks"
	"policy-opa-pdp/pkg/model"
	"testing"
)

// TestSendPdpUpdateResponse_Success tests SendPdpUpdateResponse for a successful response
func TestSendPdpUpdateResponse_Success(t *testing.T) {

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}

	err := SendPdpUpdateResponse(mockSender, pdpUpdate)
	assert.NoError(t, err)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.Anything)
}

// TestSendPdpUpdateResponse_Failure tests SendPdpUpdateResponse when SendPdpStatus fails
func TestSendPdpUpdateResponse_Failure(t *testing.T) {

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("mock send error"))

	pdpUpdate := &model.PdpUpdate{RequestId: "test-request-id"}

	err := SendPdpUpdateResponse(mockSender, pdpUpdate)

	assert.Error(t, err)

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
