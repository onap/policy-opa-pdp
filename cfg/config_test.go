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

package cfg

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	key := "TEST_ENV"
	defaultVal := "default"
	expected := "value"

	os.Setenv(key, expected)
	defer os.Unsetenv(key)

	if val := getEnv(key, defaultVal); val != expected {
		t.Errorf("Expected %s, got %s", expected, val)
	}

	if val := getEnv("NON_EXISTENT_ENV", defaultVal); val != defaultVal {
		t.Errorf("Expected %s, got %s", defaultVal, val)
	}
}

func TestGetEnvAsInt(t *testing.T) {
	key := "TEST_INT_ENV"
	defaultVal := 10
	expected := 20

	os.Setenv(key, "20")
	defer os.Unsetenv(key)

	if val := getEnvAsInt(key, defaultVal); val != expected {
		t.Errorf("Expected %d, got %d", expected, val)
	}

	if val := getEnvAsInt("NON_EXISTENT_INT_ENV", defaultVal); val != defaultVal {
		t.Errorf("Expected %d, got %d", defaultVal, val)
	}
}

func TestGetLogLevel(t *testing.T) {
	key := "TEST_LOG_LEVEL"
	defaultVal := "info"
	expected := log.DebugLevel

	os.Setenv(key, "debug")
	defer os.Unsetenv(key)

	if val := getLogLevel(key, defaultVal); val != expected {
		t.Errorf("Expected %v, got %v", expected, val)
	}

	if val := getLogLevel("NON_EXISTENT_LOG_LEVEL", defaultVal); val != log.InfoLevel {
		t.Errorf("Expected %v, got %v", log.InfoLevel, val)
	}
}

func TestGetSaslJAASLOGINFromEnv(t *testing.T) {
	// Define mock JAASLOGIN value
	mockJAASLOGIN := `username="mockUser" password="mockPassword"`

	// Set the mock environment variable
	os.Setenv("JAASLOGIN", mockJAASLOGIN)
	defer os.Unsetenv("JAASLOGIN") // Ensure the environment variable is unset after the test

	// Call the function
	username, password := getSaslJAASLOGINFromEnv("JAASLOGIN")

	// Validate the result
	assert.Equal(t, "mockUser", username, "Expected username to match mock value")
	assert.Equal(t, "mockPassword", password, "Expected password to match mock value")
}

func TestGetSaslJAASLOGINFromEnv_InvalidEnv(t *testing.T) {
	// Set the mock environment variable with an invalid format
	mockJAASLOGIN := `username="mockUser" password=mockPassword`
	os.Setenv("JAASLOGIN", mockJAASLOGIN)
	defer os.Unsetenv("JAASLOGIN") // Ensure the environment variable is unset after the test

	// Call the function
	username, password := getSaslJAASLOGINFromEnv("JAASLOGIN")

	// Validate that the function returns empty strings for invalid input
	assert.Empty(t, username, "Expected username to be empty for invalid format")
	assert.Empty(t, password, "Expected password to be empty for invalid format")
}

func TestGetSaslJAASLOGINFromEnv_EmptyEnv(t *testing.T) {
	// Set an empty environment variable
	os.Setenv("JAASLOGIN", "")
	defer os.Unsetenv("JAASLOGIN") // Ensure the environment variable is unset after the test

	// Call the function
	username, password := getSaslJAASLOGINFromEnv("JAASLOGIN")

	// Validate that the function returns empty strings for an empty value
	assert.Empty(t, username, "Expected username to be empty for empty environment variable")
	assert.Empty(t, password, "Expected password to be empty for empty environment variable")
}

func TestGetSaslJAASLOGINFromEnv_MissingEnv(t *testing.T) {
	// Unset the environment variable to simulate missing variable
	os.Unsetenv("JAASLOGIN")

	// Call the function
	username, password := getSaslJAASLOGINFromEnv("JAASLOGIN")

	// Validate that the function returns empty strings for a missing environment variable
	assert.Empty(t, username, "Expected username to be empty for missing environment variable")
	assert.Empty(t, password, "Expected password to be empty for missing environment variable")
}
