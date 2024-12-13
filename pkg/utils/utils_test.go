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

package utils

import (
	"github.com/google/uuid"
	"testing"
)

// Positive Test Case: Valid UUIDs
func TestIsValidUUIDPositive(t *testing.T) {
	// Define valid UUID strings
	validUUIDs := []string{
		"123e4567-e89b-12d3-a456-426614174000", // Standard UUID
		uuid.New().String(),                    // Dynamically generated UUID
	}

	for _, u := range validUUIDs {
		t.Run("Valid UUID", func(t *testing.T) {
			if !IsValidUUID(u) {
				t.Errorf("Expected valid UUID, but got invalid for %s", u)
			}
		})
	}
}

// Negative Test Case: Invalid UUIDs
func TestIsValidUUIDNegative(t *testing.T) {
	// Define invalid UUID strings
	invalidUUIDs := []string{
		"123e4567-e89b-12d3-a456-42661417400",  // Invalid: missing character at the end
		"invalid-uuid-format",                  // Invalid: incorrect format
		"123e4567-e89b-12d3-a456-42661417400x", // Invalid: contains extra non-hex character
		" ",                                    // Invalid: empty string
	}

	for _, u := range invalidUUIDs {
		t.Run("Invalid UUID", func(t *testing.T) {
			if IsValidUUID(u) {
				t.Errorf("Expected invalid UUID, but got valid for %s", u)
			}
		})
	}
}
