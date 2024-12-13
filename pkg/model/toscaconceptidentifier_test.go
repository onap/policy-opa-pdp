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
	"testing"
)

// Positive test for NewToscaConceptIdentifier
func TestNewToscaConceptIdentifier_Success(t *testing.T) {
	name := "ExampleName"
	version := "1.0.0"
	id := NewToscaConceptIdentifier(name, version)

	if id.Name != name {
		t.Errorf("Expected Name: %s, got: %s", name, id.Name)
	}
	if id.Version != version {
		t.Errorf("Expected Version: %s, got: %s", version, id.Version)
	}
}

// Negative test for NewToscaConceptIdentifier with empty name and version
func TestNewToscaConceptIdentifier_Failure(t *testing.T) {
	name := ""
	version := ""
	id := NewToscaConceptIdentifier(name, version)

	if id.Name != name {
		t.Errorf("Expected Name to be empty, got: %s", id.Name)
	}
	if id.Version != version {
		t.Errorf("Expected Version to be empty, got: %s", id.Version)
	}
}

// Positive test for NewToscaConceptIdentifierFromKey
func TestNewToscaConceptIdentifierFromKey_Success(t *testing.T) {
	key := PfKey{Name: "KeyName", Version: "1.0.0"}
	id := NewToscaConceptIdentifierFromKey(key)

	if id.Name != key.Name {
		t.Errorf("Expected Name: %s, got: %s", key.Name, id.Name)
	}
	if id.Version != key.Version {
		t.Errorf("Expected Version: %s, got: %s", key.Version, id.Version)
	}
}

// Negative test for NewToscaConceptIdentifierFromKey with empty PfKey values
func TestNewToscaConceptIdentifierFromKey_Failure(t *testing.T) {
	key := PfKey{Name: "", Version: ""}
	id := NewToscaConceptIdentifierFromKey(key)

	if id.Name != key.Name {
		t.Errorf("Expected Name to be empty, got: %s", id.Name)
	}
	if id.Version != key.Version {
		t.Errorf("Expected Version to be empty, got: %s", id.Version)
	}
}

// Positive test for ToscaConceptIdentifier.ValidatePapRest
func TestToscaConceptIdentifier_ValidatePapRest_Success(t *testing.T) {
	id := NewToscaConceptIdentifier("ValidName", "1.0.0")
	err := id.ValidatePapRest()

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

// Negative test for ToscaConceptIdentifier.ValidatePapRest with invalid values
func TestToscaConceptIdentifier_ValidatePapRest_Failure(t *testing.T) {
	tests := []struct {
		id        *ToscaConceptIdentifier
		expectErr bool
	}{
		{NewToscaConceptIdentifier("", "1.0"), true},       // Missing name
		{NewToscaConceptIdentifier("ValidName", ""), true}, // Missing version
		{NewToscaConceptIdentifier("", ""), true},          // Missing name and version
	}

	for _, test := range tests {
		err := test.id.ValidatePapRest()
		if (err != nil) != test.expectErr {
			t.Errorf("ValidatePapRest() for id: %+v, got error = %v, expectErr = %v", test.id, err != nil, test.expectErr)
		}
	}
}
