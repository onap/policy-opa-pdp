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

// represent PDP response details.
// https://github.com/onap/policy-models/blob/master/models-pdp
// models-pdp/src/main/java/org/onap/policy/models/pdp/concepts/PdpResponseDetails.java
package model

type PdpResponseStatus string

const (
	Success PdpResponseStatus = "SUCCESS"
	Failure PdpResponseStatus = "FAILURE"
)

type PdpResponseDetails struct {
	ResponseTo      *string            `json:"responseTo"`
	ResponseStatus  *PdpResponseStatus `json:"responseStatus"`
	ResponseMessage *string            `json:"responseMessage"`
}
