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
	intervalMs := int64(-1000)
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	StartHeartbeatIntervalTimer(intervalMs, mockSender)
	mu.Lock()
	defer mu.Unlock()

	if ticker != nil {
		t.Log("Expected ticker to be nil for invalid interval")
	}
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
TestStopTicker_Success 3
Description: Test stopping the ticker.
Input: Ticker is running
Expected Output: The ticker stops, and the stop channel is closed.
*/
func TestStopTicker_Success(t *testing.T) {
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	StartHeartbeatIntervalTimer(1000, mockSender)

	StopTicker()
	mu.Lock()
	defer mu.Unlock()
	if ticker != nil {
		t.Errorf("Expected ticker to be nil")
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
