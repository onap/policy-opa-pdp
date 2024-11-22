// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024: Deutsche Telecom
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

type MockPdpStatusSender struct {
	mock.Mock
}

func (m *MockPdpStatusSender) SendPdpStatus(pdpStatus model.PdpStatus) error {
	return m.Called(pdpStatus).Error(0)

}

func TestSendPdpPapRegistration_Success(t *testing.T) {
	mockSender := new(mocks.PdpStatusSender)

	mockSender.On("SendPdpStatus", mock.AnythingOfType("model.PdpStatus")).Return(nil)

	err := SendPdpPapRegistration(mockSender)
	assert.NoError(t, err)
	mockSender.AssertCalled(t, "SendPdpStatus", mock.AnythingOfType("model.PdpStatus"))
}

func TestSendPdpPapRegistration_Failure(t *testing.T) {
	mockSender := new(mocks.PdpStatusSender)

	mockSender.On("SendPdpStatus", mock.AnythingOfType("model.PdpStatus")).Return(errors.New("failed To Send"))

	err := SendPdpPapRegistration(mockSender)
	assert.Error(t, err, "Expected an error for failure")
	assert.EqualError(t, err, "failed To Send", "Error messages should match")
	mockSender.AssertCalled(t, "SendPdpStatus", mock.AnythingOfType("model.PdpStatus"))
}
