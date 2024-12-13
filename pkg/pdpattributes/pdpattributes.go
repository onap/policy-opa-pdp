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

// The pdpattributes package provides utilities for managing and configuring attributes related to the
// Policy Decision Point (PDP). This includes generating unique PDP names, and setting or retrieving
// subgroup and heartbeat interval values.
package pdpattributes

import (
	"github.com/google/uuid"
	"policy-opa-pdp/pkg/log"
)

var (
	PdpName              string // A unique identifier for the PDP instance
	PdpSubgroup          string
	PdpHeartbeatInterval int64 // The interval (in seconds) at which the PDP sends heartbeat signals
)

func init() {
	PdpName = GenerateUniquePdpName()
	log.Debugf("Name: %s", PdpName)
}

// Generates a unique PDP name by appending a randomly generated UUID
func GenerateUniquePdpName() string {
	return "opa-" + uuid.New().String()
}

// sets the Pdp Subgroup retrieved from the message from Pap
func SetPdpSubgroup(pdpsubgroup string) {
	PdpSubgroup = pdpsubgroup
}

// Retrieves the current PDP subgroup value.
func GetPdpSubgroup() string {
	return PdpSubgroup
}

// sets the PdpHeratbeatInterval retrieved from the message from Pap
func SetPdpHeartbeatInterval(pdpHeartbeatInterval int64) {
	PdpHeartbeatInterval = pdpHeartbeatInterval
}

// Retrieves the current PDP heartbeat interval value.
func GetPdpHeartbeatInterval() int64 {
	return PdpHeartbeatInterval

}
