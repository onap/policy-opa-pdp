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

// the possible values for health status of PDP.
// https://github.com/onap/policy-models/blob/master/models-pdp
// models-pdp/src/main/java/org/onap/policy/models/pdp/enums/PdpHealthStatus.java
package model

import (
	"encoding/json"
	"fmt"
)

// PdpHealthStatus represents the possible values for the health status of PDP.
type PdpHealthStatus int

// Enumerate the possible PDP health statuses
const (
	Healthy PdpHealthStatus = iota
	NotHealthy
	TestInProgress
	Unknown
)

// String representation of PdpHealthStatus
func (status PdpHealthStatus) String() string {
	switch status {
	case Healthy:
		return "HEALTHY"
	case NotHealthy:
		return "NOT_HEALTHY"
	case TestInProgress:
		return "TEST_IN_PROGRESS"
	case Unknown:
		return "UNKNOWN"
	default:
		return fmt.Sprintf("Unknown PdpHealthStatus: %d", status)
	}
}

func (p PdpHealthStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}
