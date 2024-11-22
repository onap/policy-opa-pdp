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
	"errors"
	"testing"
)

func (p *PdpStatus) Validate() error {
	if p.PdpType == "" {
		return errors.New("PdpType is required")
	}

	// Check if State is set to a valid non-zero value
	if p.State != Passive && p.State != Safe && p.State != Test && p.State != Active && p.State != Terminated {
		return errors.New("State is required and must be a valid PdpState")
	}

	// Check if Healthy is set to a valid non-zero value
	if p.Healthy != Healthy && p.Healthy != NotHealthy && p.Healthy != TestInProgress && p.Healthy != Unknown {
		return errors.New("Healthy status is required and must be a valid PdpHealthStatus")
	}

	if p.Name == "" {
		return errors.New("Name is required")
	}
	if p.RequestID == "" {
		return errors.New("RequestID is required")
	}
	if p.PdpGroup == "" {
		return errors.New("PdpGroup is required")
	}
	if p.TimestampMs == "" {
		return errors.New("TimestampMs is required")
	}

	return nil
}

// TestPdpStatusSerialization_Positive tests the successful serialization of PdpStatus.
func TestPdpStatusSerialization_Success(t *testing.T) {
	pdpStatus := PdpStatus{
		MessageType: PDP_STATUS,
		PdpType:     "examplePdpType",
		State:       Active,
		Healthy:     Healthy,
		Description: "PDP is healthy",
		PdpResponse: nil, // Set to nil for simplicity
		Policies:    []ToscaConceptIdentifier{},
		Name:        "ExamplePDP",
		RequestID:   "12345",
		PdpGroup:    "Group1",
		PdpSubgroup: nil,
		TimestampMs: "1633017600000",
	}

	_, err := json.Marshal(pdpStatus)
	if err != nil {
		t.Errorf("Expected no error while marshaling valid PdpStatus, got: %v", err)
	}
}

// TestPdpStatusSerialization_Negative tests the serialization of PdpStatus with invalid fields.
func TestPdpStatusValidation_Failure(t *testing.T) {
	// Example of invalid state and health strings that will fail conversion
	state, err := ConvertStringToEnumState("INVALID_STATE")
	if err == nil {
		t.Fatal("Expected error for invalid state")
	}

	// Example with missing fields or invalid enums
	pdpStatus := PdpStatus{
		PdpType:     "",
		State:       state,
		Name:        "",
		RequestID:   "",
		PdpGroup:    "",
		TimestampMs: "",
	}

	err = pdpStatus.Validate()
	if err == nil {
		t.Error("Expected an error while validating invalid PdpStatus, but got none")
	}
}

func (p *PdpUpdate) Validate() error {
	if p.Source == "" {
		return errors.New("Source is required")
	}
	if p.PdpHeartbeatIntervalMs <= 0 {
		return errors.New("PdpHeartbeatIntervalMs must be a positive integer")
	}
	if p.MessageType == "" {
		return errors.New("MessageType is required")
	}
	if len(p.PoliciesToBeDeloyed) == 0 {
		return errors.New("PoliciesToBeDeloyed is required and must contain at least one policy")
	}
	if p.Name == "" {
		return errors.New("Name is required")
	}
	if p.TimestampMs <= 0 {
		return errors.New("TimestampMs is required and must be a positive integer")
	}
	if p.PdpGroup == "" {
		return errors.New("PdpGroup is required")
	}
	if p.PdpSubgroup == "" {
		return errors.New("PdpSubgroup is required")
	}
	if p.RequestId == "" {
		return errors.New("RequestId is required")
	}

	return nil
}

// TestPdpUpdateSerialization_Positive tests the successful serialization of PdpUpdate.
func TestPdpUpdateSerialization_Success(t *testing.T) {
	pdpUpdate := PdpUpdate{
		Source:                 "source1",
		PdpHeartbeatIntervalMs: 5000,
		MessageType:            "PDP_UPDATE",
		PoliciesToBeDeloyed:    []string{"policy1", "policy2"},
		Name:                   "ExamplePDP",
		TimestampMs:            1633017600000,
		PdpGroup:               "Group1",
		PdpSubgroup:            "SubGroup1",
		RequestId:              "54321",
	}

	_, err := json.Marshal(pdpUpdate)
	if err != nil {
		t.Errorf("Expected no error while marshaling valid PdpUpdate, got: %v", err)
	}
}

// TestPdpUpdateSerialization_Negative tests the serialization of PdpUpdate with invalid fields.
func TestPdpUpdateSerialization_Failure(t *testing.T) {
	pdpUpdate := PdpUpdate{
		Source:                 "",
		PdpHeartbeatIntervalMs: 5000,
		MessageType:            "",
		PoliciesToBeDeloyed:    nil,
		Name:                   "",
		TimestampMs:            0,
		PdpGroup:               "",
		PdpSubgroup:            "",
		RequestId:              "",
	}
	err := pdpUpdate.Validate()
	if err == nil {
		t.Error("Expected an error while validating invalid PdpStatus, but got none")
	}

}

func (p *PdpStateChange) Validate() error {
	if p.Source == "" {
		return errors.New("Source is required")
	}
	if p.State == "" {
		return errors.New("State is required")
	}
	if p.MessageType == "" {
		return errors.New("MessageType is required")
	}
	if p.Name == "" {
		return errors.New("Name is required")
	}
	if p.TimestampMs <= 0 {
		return errors.New("TimestampMs is required and must be a positive integer")
	}
	if p.PdpGroup == "" {
		return errors.New("PdpGroup is required")
	}
	if p.PdpSubgroup == "" {
		return errors.New("PdpSubgroup is required")
	}
	if p.RequestId == "" {
		return errors.New("RequestId is required")
	}

	return nil
}

// TestPdpStateChangeSerialization_Positive tests the successful serialization of PdpStateChange.
func TestPdpStateChangeSerialization_Success(t *testing.T) {
	pdpStateChange := PdpStateChange{
		Source:      "source1",
		State:       "active",
		MessageType: "PDP_STATE_CHANGE",
		Name:        "ExamplePDP",
		TimestampMs: 1633017600000,
		PdpGroup:    "Group1",
		PdpSubgroup: "SubGroup1",
		RequestId:   "98765",
	}

	_, err := json.Marshal(pdpStateChange)
	if err != nil {
		t.Errorf("Expected no error while marshaling valid PdpStateChange, got: %v", err)
	}
}

// TestPdpStateChangeSerialization_Negative tests the serialization of PdpStateChange with invalid fields.
func TestPdpStateChangeSerialization_Failure(t *testing.T) {
	pdpStateChange := PdpStateChange{
		Source:      "",
		State:       "",
		MessageType: "",
		Name:        "",
		TimestampMs: 0,
		PdpGroup:    "",
		PdpSubgroup: "",
		RequestId:   "",
	}
	err := pdpStateChange.Validate()
	if err == nil {
		t.Error("Expected an error while validating invalid PdpStatus, but got none")
	}
}
