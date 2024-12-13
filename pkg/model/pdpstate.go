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

// hold the possible values for state of PDP.
// https://github.com/onap/policy-models/blob/master/models-pdp
// models-pdp/src/main/java/org/onap/policy/models/pdp/enums/PdpState.java
package model

import (
	"encoding/json"
	"fmt"
)

// PdpState represents the possible values for the state of PDP.
type PdpState int

// Enumerate the possible PDP states
const (
	Passive PdpState = iota
	Safe
	Test
	Active
	Terminated
)

// String representation of PdpState
func (state PdpState) String() string {
	switch state {
	case Passive:
		return "PASSIVE"
	case Safe:
		return "SAFE"
	case Test:
		return "TEST"
	case Active:
		return "ACTIVE"
	case Terminated:
		return "TERMINATED"
	default:
		return fmt.Sprintf("Unknown PdpState: %d", state)
	}
}

func (s PdpState) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func ConvertStringToEnumState(state string) (PdpState, error) {
	switch state {
	case "PASSIVE":
		return Passive, nil
	case "SAFE":
		return Safe, nil
	case "TEST":
		return Test, nil
	case "ACTIVE":
		return Active, nil
	case "TERMINATED":
		return Terminated, nil
	default:
		return -1, fmt.Errorf("Unknown PdpState: %s", state)
	}
}
