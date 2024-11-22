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
//

package model

import (
	"encoding/json"
	"testing"
)

// Positive test for JSON marshaling of PdpResponseDetails with all fields populated
func TestPdpResponseDetails_MarshalJSON_Success(t *testing.T) {
	responseTo := "requestID123"
	responseMessage := "Operation completed successfully"
	responseStatus := Success

	details := PdpResponseDetails{
		ResponseTo:      &responseTo,
		ResponseStatus:  &responseStatus,
		ResponseMessage: &responseMessage,
	}

	expectedJSON := `{"responseTo":"requestID123","responseStatus":"SUCCESS","responseMessage":"Operation completed successfully"}`
	got, err := json.Marshal(details)
	if err != nil {
		t.Errorf("json.Marshal() error = %v", err)
	}

	if string(got) != expectedJSON {
		t.Errorf("json.Marshal() = %v, want %v", string(got), expectedJSON)
	}
}

// Negative test for JSON marshaling of PdpResponseDetails with nil fields
func TestPdpResponseDetails_MarshalJSON_Failure(t *testing.T) {
	details := PdpResponseDetails{}

	expectedJSON := `{"responseTo":null,"responseStatus":null,"responseMessage":null}`
	got, err := json.Marshal(details)
	if err != nil {
		t.Errorf("json.Marshal() error = %v", err)
	}

	if string(got) != expectedJSON {
		t.Errorf("json.Marshal() = %v, want %v", string(got), expectedJSON)
	}
}

// Positive test for PdpResponseStatus constants
func TestPdpResponseStatus_Success(t *testing.T) {
	tests := []struct {
		status   PdpResponseStatus
		expected string
	}{
		{Success, "SUCCESS"},
		{Failure, "FAILURE"},
	}

	for _, test := range tests {
		if string(test.status) != test.expected {
			t.Errorf("PdpResponseStatus = %v, want %v", test.status, test.expected)
		}
	}
}

// Negative test for invalid PdpResponseStatus
func TestPdpResponseStatus_Failure(t *testing.T) {
	invalidStatus := PdpResponseStatus("INVALID")
	expected := "INVALID"

	if string(invalidStatus) != expected {
		t.Errorf("PdpResponseStatus = %v, want %v", invalidStatus, expected)
	}
}
