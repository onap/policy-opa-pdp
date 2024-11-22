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

// Positive test cases for PdpState.String
func TestPdpState_String_Success(t *testing.T) {
	tests := []struct {
		state    PdpState
		expected string
	}{
		{Passive, "PASSIVE"},
		{Safe, "SAFE"},
		{Test, "TEST"},
		{Active, "ACTIVE"},
		{Terminated, "TERMINATED"},
	}

	for _, test := range tests {
		got := test.state.String()
		if got != test.expected {
			t.Errorf("PdpState.String() = %v, want %v", got, test.expected)
		}
	}
}

// Negative test case for PdpState.String
func TestPdpState_String_Failure(t *testing.T) {
	state := PdpState(100) // Unknown state
	expected := "Unknown PdpState: 100"
	got := state.String()
	if got != expected {
		t.Errorf("PdpState.String() = %v, want %v", got, expected)
	}
}

// Positive test cases for PdpState.MarshalJSON
func TestPdpState_MarshalJSON_Success(t *testing.T) {
	tests := []struct {
		state    PdpState
		expected string
	}{
		{Passive, `"PASSIVE"`},
		{Safe, `"SAFE"`},
		{Test, `"TEST"`},
		{Active, `"ACTIVE"`},
		{Terminated, `"TERMINATED"`},
	}

	for _, test := range tests {
		got, err := json.Marshal(test.state)
		if err != nil {
			t.Errorf("json.Marshal() error = %v", err)
			continue
		}

		if string(got) != test.expected {
			t.Errorf("json.Marshal() = %v, want %v", string(got), test.expected)
		}
	}
}

// Negative test case for PdpState.MarshalJSON
func TestPdpState_MarshalJSON_Failure(t *testing.T) {
	state := PdpState(100) // Unknown state
	expected := `"Unknown PdpState: 100"`

	got, err := json.Marshal(state)
	if err != nil {
		t.Errorf("json.Marshal() error = %v", err)
	} else if string(got) != expected {
		t.Errorf("json.Marshal() = %v, want %v", string(got), expected)
	}
}

// Positive test cases for ConvertStringToEnumState
func TestConvertStringToEnumState_Success(t *testing.T) {
	tests := []struct {
		input    string
		expected PdpState
	}{
		{"PASSIVE", Passive},
		{"SAFE", Safe},
		{"TEST", Test},
		{"ACTIVE", Active},
		{"TERMINATED", Terminated},
	}

	for _, test := range tests {
		got, err := ConvertStringToEnumState(test.input)
		if err != nil {
			t.Errorf("ConvertStringToEnumState(%v) unexpected error = %v", test.input, err)
			continue
		}
		if got != test.expected {
			t.Errorf("ConvertStringToEnumState(%v) = %v, want %v", test.input, got, test.expected)
		}
	}
}

// Negative test case for ConvertStringToEnumState
func TestConvertStringToEnumState_Failure(t *testing.T) {
	input := "UNKNOWN" // Invalid state
	_, err := ConvertStringToEnumState(input)
	if err == nil {
		t.Errorf("ConvertStringToEnumState(%v) expected error, got nil", input)
	}
}
