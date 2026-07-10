// -
//
//	========================LICENSE_START=================================
//	Copyright (C) 2024-2025: Deutsche Telekom
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	     http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
//	SPDX-License-Identifier: Apache-2.0
//	========================LICENSE_END===================================
package publisher

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"policy-opa-pdp/pkg/kafkacomm/publisher/mocks"
	"policy-opa-pdp/pkg/policymap"
	"testing"
)

/*
Success Case 1
TestStartHeartbeatIntervalTimer_ValidInterval
Description: Test starting the heartbeat interval timer with a valid interval.
Input: intervalMs = 1000
Expected Output: The ticker starts with an interval of 1000 milliseconds, and heartbeat messages are sent at this interval.
*/
func TestStartHeartbeatIntervalTimer_ValidInterval(t *testing.T) {
	intervalMs := int64(1000)
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	StartHeartbeatIntervalTimer(intervalMs, mockSender)
	mu.Lock()
	defer mu.Unlock()
	if ticker == nil {
		t.Errorf("Expected ticker to be initialized")
	}
	if currentInterval != intervalMs {
		t.Errorf("Expected currentInterval to be %d, got %d", intervalMs, currentInterval)
	}
}

/*
Failure Case 1
TestStartHeartbeatIntervalTimer_InvalidInterval
Description: Test starting the heartbeat interval timer with an invalid interval.
Input: intervalMs = -1000
Expected Output: The function should handle the invalid interval gracefully, possibly by logging an error message and not starting the ticker.
*/
func TestStartHeartbeatIntervalTimer_InvalidInterval(t *testing.T) {
	// Start a valid ticker first so we can verify a negative interval does NOT
	// orphan it by nil-ing the package-level ticker variable.
	validSender := new(mocks.PdpStatusSender)
	validSender.On("SendPdpStatus", mock.Anything).Return(nil)
	StartHeartbeatIntervalTimer(1000, validSender)

	intervalMs := int64(-1000)
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	StartHeartbeatIntervalTimer(intervalMs, mockSender)
	mu.Lock()
	// Corrected contract: a negative interval must return early WITHOUT nil-ing
	// the running ticker (the old code set ticker=nil, orphaning the goroutine).
	assert.NotNil(t, ticker, "A negative interval must not nil the running ticker")
	mu.Unlock()
	StopTicker()
}

/*
TestSendPDPHeartBeat_Success 2
Description: Test sending a heartbeat successfully.
Input: Valid pdpStatus object
Expected Output: Heartbeat message is sent successfully, and a debug log "Message sent successfully" is generated.
*/
func TestSendPDPHeartBeat_Success(t *testing.T) {
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	err := sendPDPHeartBeat(mockSender)
	assert.NoError(t, err)
}

/*
TestSendPDPHeartBeat_Failure 2
Description: Test failing to send a heartbeat.
Input: Invalid pdpStatus object or network failure
Expected Output: An error occurs while sending the heartbeat, and a warning log "Error producing message: ..." is generated.
*/
func TestSendPDPHeartBeat_Failure(t *testing.T) {
	// Mock SendPdpStatus to return an error
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Error producing message"))
	err := sendPDPHeartBeat(mockSender)
	assert.Error(t, err)
}

/*
TestsendPDPHeartBeat_Success 3
Description: Test sending a heartbeat successfully with some deployed policies.
Input: Valid pdpStatus object
Expected Output: Heartbeat message is sent successfully, and a debug log "Message sent successfully" is generated.
*/
func TestSendPDPHeartBeat_SuccessSomeDeployedPolicies(t *testing.T) {
	// Setup mock Policymap
	mockPolicymap := new(MockPolicymap)
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	policymap.LastDeployedPolicies = "some-policies"
	// Set mock behavior for policymap
	mockPolicymap.On("ExtractDeployedPolicies", mock.Anything).Return(nil)
	err := sendPDPHeartBeat(mockSender)
	assert.NoError(t, err)
}

/*
TestsendPDPHeartBeat_Success 4
Description: Test sending a heartbeat successfully with no deployed policies.
Input: Valid pdpStatus object
Expected Output: Heartbeat message is sent successfully, and a debug log "Message sent successfully" is generated.
*/
func TestSendPDPHeartBeat_SuccessNoDeployedPolicies(t *testing.T) {
	// Setup mock Policymap
	mockPolicymap := new(MockPolicymap)
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	policymap.LastDeployedPolicies = ""
	// Set mock behavior for policymap
	mockPolicymap.On("ExtractDeployedPolicies", mock.Anything).Return(nil)
	err := sendPDPHeartBeat(mockSender)
	assert.NoError(t, err)
}

/*
TestStopTicker_Success 3
Description: Test stopping the ticker.
Input: Ticker is running
Expected Output: The ticker stops, and the stop channel is closed.
*/
func TestStopTicker_Success(t *testing.T) {
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	StartHeartbeatIntervalTimer(1000, mockSender)
	// StopTicker sends to stopChan which causes the goroutine to exit and call
	// defer wg.Done() — no manual wg.Done() needed here (the old wg.Done() call
	// caused a negative WaitGroup counter).
	StopTicker()
	mu.Lock()
	defer mu.Unlock()
	if stopChan != nil {
		t.Errorf("Expected stopChan to be nil after stop")
	}
}

/*
TestStopTicker_NotRunning 3
Description: Test stopping the ticker when it is not running.
Input: Ticker is not running
Expected Output: The function should handle this case gracefully, possibly by logging a debug message indicating that the ticker is not running.
*/
func TestStopTicker_NotRunning(t *testing.T) {
	StopTicker()
	mu.Lock()
	defer mu.Unlock()
}
func TestStartHeartbeatIntervalTimer_TickerAlreadyRunning(t *testing.T) {
	intervalMs := int64(1000)
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	// Start the ticker for the first time
	StartHeartbeatIntervalTimer(intervalMs, mockSender)
	StartHeartbeatIntervalTimer(intervalMs, mockSender)
	if currentInterval != intervalMs {
		t.Errorf("Expected ticker to not restart, currentInterval is %d, expected %d", currentInterval, intervalMs)
	}
	assert.NotNil(t, ticker, "Expected ticker to be running but it is nil")
}
func TestStartHeartbeatIntervalTimer_TickerAlreadyRunning_Case2(t *testing.T) {
	intervalMs := int64(1000)
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	// Start the ticker for the first time
	StartHeartbeatIntervalTimer(intervalMs, mockSender)
	// Start it again
	StartHeartbeatIntervalTimer(int64(201), mockSender)
	assert.NotNil(t, ticker, "Expected ticker to be running but it is nil")
}

/*
TestStartHeartbeat_ZeroIntervalNoPanic
Description: When called with intervalMs=0 and currentInterval=0 (clean state),
the function must not panic by calling time.NewTicker(0). Instead it should
log an error and return.
*/
func TestStartHeartbeat_ZeroIntervalNoPanic(t *testing.T) {
	StopTicker() // ensure clean state; currentInterval stays 0
	assert.NotPanics(t, func() {
		StartHeartbeatIntervalTimer(0, new(mocks.PdpStatusSender))
	})
	StopTicker()
}
