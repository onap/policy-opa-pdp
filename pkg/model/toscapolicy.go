// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2025: Deutsche Telekom
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

import ()

type ToscaPolicy struct {
	Type        string           `json:"type"`
	TypeVersion string           `json:"type_version"`
	Properties  PolicyProperties `json:"properties"`
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	Metadata    Metadata         `json:"metadata"`
}

type PolicyProperties struct {
	Data   map[string]string `json:"data"`
	Policy map[string]string `json:"policy"`
}

type Metadata struct {
	PolicyID      string `json:"policy-id"`
	PolicyVersion string `json:"policy-version"`
}
