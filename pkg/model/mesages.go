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

// Defines structure for messages exchanged between PDP and PAP
// Refer: https://docs.onap.org/projects/onap-policy-parent/en/latest/pap/InternalPapPdp.html
// for attribute level details of each message.
package model

import (
	"encoding/json"
	"fmt"
)

// PdpMessageType represents the type of PDP message.
type PdpMessageType int

// Enumerate the possible PDP message types
// https://github.com/onap/policy-models
// models-pdp/src/main/java/org/onap/policy/models/pdp/enums/PdpMessageType.java
const (
	PDP_STATUS PdpMessageType = iota
	PDP_UPDATE
	PDP_STATE_CHANGE
	PDP_HEALTH_CHECK
	PDP_TOPIC_CHECK
)

// String representation of PdpMessageType
func (msgType PdpMessageType) String() string {
	switch msgType {
	case PDP_STATUS:
		return "PDP_STATUS"
	case PDP_UPDATE:
		return "PDP_UPDATE"
	case PDP_STATE_CHANGE:
		return "PDP_STATE_CHANGE"
	case PDP_HEALTH_CHECK:
		return "PDP_HEALTH_CHECK"
	case PDP_TOPIC_CHECK:
		return "PDP_TOPIC_CHECK"
	default:
		return fmt.Sprintf("Unknown PdpMessageType: %d", msgType)
	}
}

func (p PdpMessageType) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

// PdpStatus represents the PDP_STATUS message sent from PDP to PAP.
// https://github.com/onap/policy-models
// models-pdp/src/main/java/org/onap/policy/models/pdp/concepts/PdpStatus.java
type PdpStatus struct {
	MessageType            PdpMessageType           `json:"messageName"`
	PdpType                string                   `json:"pdpType"`
	State                  PdpState                 `json:"state"`
	Healthy                PdpHealthStatus          `json:"healthy"`
	Description            string                   `json:"description"`
	PdpResponse            *PdpResponseDetails      `json:"response"`
	Policies               []ToscaConceptIdentifier `json:"policies"`
	Name                   string                   `json:"name"`
	RequestID              string                   `json:"requestId"`
	PdpGroup               string                   `json:"pdpGroup"`
	PdpSubgroup            *string                  `json:"pdpSubgroup"`
	TimestampMs            string                   `json:"timestampMs"`
	DeploymentInstanceInfo string                   `json:"deploymentInstanceInfo"`
}

// PDP_UPDATE sent by PAP to PDP.
// https://github.com/onap/policy-models
// models-pdp/src/main/java/org/onap/policy/models/pdp/concepts/PdpUpdate.java
type PdpUpdate struct {
	Source                 string                   `json:"source" validate:"required"`
	PdpHeartbeatIntervalMs int64                    `json:"pdpHeartbeatIntervalMs" validate:"required"`
	MessageType            string                   `json:"messageName" validate:"required"`
	PoliciesToBeDeloyed    []string                 `json:"policiesToBeDeployed" validate:"required"`
	policiesToBeUndeployed []ToscaConceptIdentifier `json:"policiesToBeUndeployed"`
	Name                   string                   `json:"name" validate:"required"`
	TimestampMs            int64                    `json:"timestampMs" validate:"required"`
	PdpGroup               string                   `json:"pdpGroup" validate:"required"`
	PdpSubgroup            string                   `json:"pdpSubgroup" validate:"required"`
	RequestId              string                   `json:"requestId" validate:"required"`
}

// PDP_STATE_CHANGE sent by PAP to PDP.
// https://github.com/onap/policy-models
// models-pdp/src/main/java/org/onap/policy/models/pdp/concepts/PdpStateChange.java
type PdpStateChange struct {
	Source      string `json:"source"`
	State       string `json:"state"`
	MessageType string `json:"messageName"`
	Name        string `json:"name"`
	TimestampMs int64  `json:"timestampMs"`
	PdpGroup    string `json:"pdpGroup"`
	PdpSubgroup string `json:"pdpSubgroup"`
	RequestId   string `json:"requestId"`
}
