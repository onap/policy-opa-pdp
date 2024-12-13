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

package handler

import (
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpstate"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockPdpStatusSender is a mock implementation of the PdpStatusSender interface
type MockPdpStatusSender struct {
	mock.Mock
}

func (m *MockPdpStatusSender) SendStateChangeResponse(p *publisher.PdpStatusSender, pdpStateChange *model.PdpStateChange) error {
	args := m.Called(p, pdpStateChange)
	return args.Error(0)
}

func (m *MockPdpStatusSender) SendPdpStatus(status model.PdpStatus) error {
	args := m.Called(status)
	return args.Error(0)
}

func TestPdpStateChangeMessageHandler(t *testing.T) {

	// Create a mock PdpStatusSender
	mockSender := new(MockPdpStatusSender)

	// Define test cases
	tests := []struct {
		name          string
		message       []byte
		expectedState string
		mockError     error
		expectError   bool
	}{
		{
			name:          "Valid state change",
			message:       []byte(`{"state":"ACTIVE"}`),
			expectedState: "ACTIVE",
			mockError:     nil,
			expectError:   false,
		},
		{
			name:        "Invalid JSON",
			message:     []byte(`{"state":}`),
			mockError:   nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up the mock to return the expected error
			mockSender.On("SendStateChangeResponse", mock.Anything, mock.Anything).Return(tt.mockError)
			mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

			// Call the handler
			err := PdpStateChangeMessageHandler(tt.message, mockSender)

			// Check the results
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedState, pdpstate.GetState().String())
			}

		})
	}
}
