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

// The publisher package is responsible for managing periodic heartbeat messages for the
// Open Policy Agent (OPA) Policy Decision Point (PDP) and publishing the PDP's status to relevant channels.
// It provides functions to initialize, manage, and stop timers for sending heartbeat messages,
// ensuring the PDP communicates its health and state periodically.
package publisher

import (
	"fmt"
	"github.com/google/uuid"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpattributes"
	"policy-opa-pdp/pkg/pdpstate"
	"sync"
	"time"
)

var (
	ticker          *time.Ticker
	stopChan        chan bool
	currentInterval int64
	mu              sync.Mutex
)

// Initializes a timer that sends periodic heartbeat messages to indicate the health and state of the PDP.
func StartHeartbeatIntervalTimer(intervalMs int64, s PdpStatusSender) {
	if intervalMs <= 0 {
		log.Errorf("Invalid interval provided: %d. Interval must be greater than zero.", intervalMs)
		ticker = nil
		return
	}
	mu.Lock()
	defer mu.Unlock()

	if ticker != nil && intervalMs == currentInterval {
		log.Debug("Ticker is already running")
		return
	}

	if ticker != nil {
		ticker.Stop()
	}
	// StopTicker()
	currentInterval = intervalMs

	ticker = time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	log.Debugf("New Ticker %d", currentInterval)
	stopChan = make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				sendPDPHeartBeat(s)
			case <-stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

// Creates and sends a heartbeat message with the PDP's current state, health, and attributes
func sendPDPHeartBeat(s PdpStatusSender) error {
	pdpStatus := model.PdpStatus{
		MessageType: model.PDP_STATUS,
		PdpType:     consts.PdpType,
		State:       pdpstate.GetState(),
		Healthy:     model.Healthy,
		Name:        pdpattributes.PdpName,
		Description: "Pdp heartbeat",
		PdpGroup:    consts.PdpGroup,
		PdpSubgroup: &pdpattributes.PdpSubgroup,
	}
	pdpStatus.RequestID = uuid.New().String()
	pdpStatus.TimestampMs = fmt.Sprintf("%d", time.Now().UnixMilli())

	err := s.SendPdpStatus(pdpStatus)
	log.Debugf("Sending Heartbeat ...")
	if err != nil {
		log.Warnf("Error producing message: %v\n", err)
		return err
	} else {
		return nil
	}
}

// Stops the running ticker and terminates the goroutine managing heartbeat messages.
func StopTicker() {
	mu.Lock()
	defer mu.Unlock()
	if ticker != nil && stopChan != nil {
		stopChan <- true
		close(stopChan)
		ticker = nil
		stopChan = nil
	} else {
		log.Debugf("Ticker is not Running")
	}
}
