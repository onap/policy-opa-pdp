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

package model

import (
	"encoding/json"
	"testing"
)

// Positive test for the string representation of valid PdpHealthStatus values
func TestPdpHealthStatus_String_Success(t *testing.T) {
	tests := []struct {
		status   PdpHealthStatus
		expected string
	}{
		{Healthy, "HEALTHY"},
		{NotHealthy, "NOT_HEALTHY"},
		{TestInProgress, "TEST_IN_PROGRESS"},
		{Unknown, "UNKNOWN"},
	}

	for _, test := range tests {
		if got := test.status.String(); got != test.expected {
			t.Errorf("PdpHealthStatus.String() = %v, want %v", got, test.expected)
		}
	}
}

// Negative test for the string representation of an invalid PdpHealthStatus value
func TestPdpHealthStatus_String_Failure(t *testing.T) {
	invalidStatus := PdpHealthStatus(100)
	expected := "Unknown PdpHealthStatus: 100"

	if got := invalidStatus.String(); got != expected {
		t.Errorf("PdpHealthStatus.String() = %v, want %v", got, expected)
	}
}

// Positive test for JSON marshaling of valid PdpHealthStatus values
func TestPdpHealthStatus_MarshalJSON_Success(t *testing.T) {
	tests := []struct {
		status   PdpHealthStatus
		expected string
	}{
		{Healthy, `"HEALTHY"`},
		{NotHealthy, `"NOT_HEALTHY"`},
		{TestInProgress, `"TEST_IN_PROGRESS"`},
		{Unknown, `"UNKNOWN"`},
	}

	for _, test := range tests {
		got, err := json.Marshal(test.status)
		if err != nil {
			t.Errorf("json.Marshal() error = %v", err)
		}

		if string(got) != test.expected {
			t.Errorf("json.Marshal() = %v, want %v", string(got), test.expected)
		}
	}
}

// Negative test for JSON marshaling of an invalid PdpHealthStatus value
func TestPdpHealthStatus_MarshalJSON_Failure(t *testing.T) {
	invalidStatus := PdpHealthStatus(100)
	expected := `"Unknown PdpHealthStatus: 100"`

	got, err := json.Marshal(invalidStatus)
	if err != nil {
		t.Errorf("json.Marshal() unexpected error = %v", err)
	}

	if string(got) != expected {
		t.Errorf("json.Marshal() = %v, want %v", string(got), expected)
	}
}
