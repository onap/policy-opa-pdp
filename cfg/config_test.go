// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024-2025: Deutsche Telekom
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
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	key := "TEST_ENV"
	defaultVal := "default"
	expected := "value"

	_ = os.Setenv(key, expected)
	defer func() { _ = os.Unsetenv(key) }()

	if val := getEnv(key, defaultVal); val != expected {
		t.Errorf("Expected %s, got %s", expected, val)
	}

	if val := getEnv("NON_EXISTENT_ENV", defaultVal); val != defaultVal {
		t.Errorf("Expected %s, got %s", defaultVal, val)
	}
}

func TestGetSaslJAASLOGINFromEnv(t *testing.T) {
	// Define mock JAASLOGIN value
	mockJAASLOGIN := `username="mockUser" password="mockPassword"`

	// Set the mock environment variable
	_ = os.Setenv("JAASLOGIN", mockJAASLOGIN)
	// Ensure the environment variable is unset after the test
	defer func() { _ = os.Unsetenv("JAASLOGIN") }()

	// Call the function
	username, password := getSaslJAASLOGINFromEnv()

	// Validate the result
	assert.Equal(t, "mockUser", username, "Expected username to match mock value")
	assert.Equal(t, "mockPassword", password, "Expected password to match mock value")
}

func TestGetSaslJAASLOGINFromEnv_InvalidEnv(t *testing.T) {
	// Set the mock environment variable with an invalid format
	mockJAASLOGIN := `username="mockUser" password=mockPassword`
	_ = os.Setenv("JAASLOGIN", mockJAASLOGIN)
	// Ensure the environment variable is unset after the test
	defer func() { _ = os.Unsetenv("JAASLOGIN") }()

	// Call the function
	username, password := getSaslJAASLOGINFromEnv()

	// Validate that the function returns empty strings for invalid input
	assert.Empty(t, username, "Expected username to be empty for invalid format")
	assert.Empty(t, password, "Expected password to be empty for invalid format")
}

func TestGetSaslJAASLOGINFromEnv_EmptyEnv(t *testing.T) {
	// Set an empty environment variable
	_ = os.Setenv("JAASLOGIN", "")
	defer func() { _ = os.Unsetenv("JAASLOGIN") }() // Ensure the environment variable is unset after the test

	// Call the function
	username, password := getSaslJAASLOGINFromEnv()

	// Validate that the function returns empty strings for an empty value
	assert.Empty(t, username, "Expected username to be empty for empty environment variable")
	assert.Empty(t, password, "Expected password to be empty for empty environment variable")
}

func TestGetSaslJAASLOGINFromEnv_MissingEnv(t *testing.T) {
	// Unset the environment variable to simulate missing variable
	_ = os.Unsetenv("JAASLOGIN")

	// Call the function
	username, password := getSaslJAASLOGINFromEnv()

	// Validate that the function returns empty strings for a missing environment variable
	assert.Empty(t, username, "Expected username to be empty for missing environment variable")
	assert.Empty(t, password, "Expected password to be empty for missing environment variable")
}

func TestConfig_NoHardcodedPasswordDefault(t *testing.T) {
	// Go init functions cannot be called explicitly (they are not in scope as
	// callable identifiers), so we cannot re-invoke init() here.  Instead we
	// rely on the fact that init() already ran when this package was loaded by
	// the test binary.  If API_PASSWORD was absent at load time and init() uses
	// a hardcoded non-empty default, Password will be non-empty here.
	//
	// If API_PASSWORD is set in the outer environment we skip: we cannot tell
	// whether Password came from the env var or a hardcoded default.
	if _, set := os.LookupEnv("API_PASSWORD"); set {
		t.Skip("API_PASSWORD is set in environment; cannot verify absence of hardcoded default")
	}
	assert.Empty(t, Password, "API_PASSWORD must have no hardcoded default (fail-closed)")
}

// withValidConfig installs a configuration that Validate accepts and restores whatever the
// package-level init left behind, so a case only has to state the one field it breaks.
func withValidConfig(t *testing.T) {
	t.Helper()

	saved := []struct {
		target *string
		value  string
	}{
		{&Username, Username}, {&Password, Password}, {&BootstrapServer, BootstrapServer},
		{&Topic, Topic}, {&PatchTopic, PatchTopic}, {&GroupId, GroupId},
		{&PatchGroupId, PatchGroupId}, {&UseSASLForKAFKA, UseSASLForKAFKA},
		{&KAFKA_USERNAME, KAFKA_USERNAME}, {&KAFKA_PASSWORD, KAFKA_PASSWORD},
	}
	t.Cleanup(func() {
		for _, s := range saved {
			*s.target = s.value
		}
	})

	Username = "policyadmin"
	Password = "somepassword"
	BootstrapServer = "kafka:9092"
	Topic = "policy-pdp-pap"
	PatchTopic = "opa-pdp-data"
	GroupId = "opa-pdp-1"
	PatchGroupId = "opa-pdp-data-1"
	UseSASLForKAFKA = "false"
	KAFKA_USERNAME = ""
	KAFKA_PASSWORD = ""
}

func TestValidate_AcceptsADefaultConfiguration(t *testing.T) {
	withValidConfig(t)

	assert.NoError(t, Validate())
}

func TestValidate_RejectsMissingRequiredValues(t *testing.T) {
	tests := []struct {
		name    string
		break_  func()
		message string
	}{
		{"empty API_USER", func() { Username = "" }, "API_USER must not be empty"},
		{"empty API_PASSWORD", func() { Password = "" }, "API_PASSWORD must not be empty"},
		{"empty KAFKA_URL", func() { BootstrapServer = "" }, "KAFKA_URL must not be empty"},
		{"empty PAP_TOPIC", func() { Topic = "" }, "PAP_TOPIC must not be empty"},
		{"empty PATCH_TOPIC", func() { PatchTopic = "" }, "PATCH_TOPIC must not be empty"},
		{"empty GROUPID", func() { GroupId = "" }, "GROUPID must not be empty"},
		{"empty PATCH_GROUPID", func() { PatchGroupId = "" }, "PATCH_GROUPID must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withValidConfig(t)
			tt.break_()

			err := Validate()
			assert.ErrorContains(t, err, tt.message)
		})
	}
}

// Every problem has to be reported at once; one problem per restart is what makes fixing a
// deployment tedious enough to skip.
func TestValidate_ReportsEveryProblemAtOnce(t *testing.T) {
	withValidConfig(t)
	Password = ""
	Topic = ""
	BootstrapServer = "kafka"

	err := Validate()
	assert.ErrorContains(t, err, "API_PASSWORD must not be empty")
	assert.ErrorContains(t, err, "PAP_TOPIC must not be empty")
	assert.ErrorContains(t, err, `KAFKA_URL entry "kafka" must be host:port`)
}

func TestValidate_BootstrapServer(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		message string
	}{
		{"single broker", "kafka:9092", ""},
		{"broker list", "kafka-0:9092,kafka-1:9092", ""},
		{"list with spaces", "kafka-0:9092, kafka-1:9092", ""},
		{"ipv6", "[::1]:9092", ""},
		{"no port", "kafka", "must be host:port"},
		{"scheme", "http://kafka:9092", "without a scheme"},
		{"non-numeric port", "kafka:kafka", `invalid port "kafka"`},
		{"port out of range", "kafka:99999", `invalid port "99999"`},
		{"one bad entry in a list", "kafka-0:9092,kafka-1", "must be host:port"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withValidConfig(t)
			BootstrapServer = tt.value

			err := Validate()
			if tt.message == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.message)
		})
	}
}

// The Kafka clients compare this against the literal "true", so anything else that a human
// reads as true silently turns SASL off.
func TestValidate_UseSASLForKAFKA(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		username string
		password string
		message  string
	}{
		{"false", "false", "", "", ""},
		{"true with credentials", "true", "user", "pass", ""},
		{"true without credentials", "true", "", "", "no credentials were parsed from JAASLOGIN"},
		{"true without password", "true", "user", "", "no credentials were parsed from JAASLOGIN"},
		{"capitalised", "True", "user", "pass", `must be exactly "true" or "false", got "True"`},
		{"numeric", "1", "user", "pass", `got "1"`},
		{"empty", "", "", "", `got ""`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withValidConfig(t)
			UseSASLForKAFKA = tt.value
			KAFKA_USERNAME = tt.username
			KAFKA_PASSWORD = tt.password

			err := Validate()
			if tt.message == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.message)
		})
	}
}

func TestSummary_RedactsCredentials(t *testing.T) {
	withValidConfig(t)
	Password = "zb!XztG34"
	KAFKA_PASSWORD = "kafka-secret"

	summary := Summary()

	assert.NotContains(t, summary, "zb!XztG34")
	assert.NotContains(t, summary, "kafka-secret")
	assert.Contains(t, summary, "API_PASSWORD=<set>")
	assert.Contains(t, summary, "JAASLOGIN=<set>")
	assert.Contains(t, summary, "API_USER=policyadmin")
	assert.Contains(t, summary, "KAFKA_URL=kafka:9092")
}

func TestSummary_ReportsUnsetCredentials(t *testing.T) {
	withValidConfig(t)
	Password = ""
	KAFKA_PASSWORD = ""

	summary := Summary()

	assert.Contains(t, summary, "API_PASSWORD=<unset>")
	assert.Contains(t, summary, "JAASLOGIN=<unset>")
}

func TestGetEnvAsBool(t *testing.T) {
	t.Run("valid boolean true", func(t *testing.T) {
		_ = os.Setenv("USE_KAFKA_FOR_PATCH", "true")
		defer func() { _ = os.Unsetenv("USE_KAFKA_FOR_PATCH") }()

		result := getEnvAsBool("USE_KAFKA_FOR_PATCH", false)
		assert.True(t, result)
	})

	t.Run("valid boolean false", func(t *testing.T) {
		_ = os.Setenv("USE_KAFKA_FOR_PATCH", "false")
		defer func() { _ = os.Unsetenv("USE_KAFKA_FOR_PATCH") }()

		result := getEnvAsBool("USE_KAFKA_FOR_PATCH", true)
		assert.False(t, result)
	})

	t.Run("invalid boolean value", func(t *testing.T) {
		_ = os.Setenv("USE_KAFKA_FOR_PATCH", "notabool")
		defer func() { _ = os.Unsetenv("USE_KAFKA_FOR_PATCH") }()

		result := getEnvAsBool("USE_KAFKA_FOR_PATCH", true)
		assert.True(t, result) // should return default (true) because parsing fails
	})

	t.Run("missing env variable", func(t *testing.T) {
		_ = os.Unsetenv("USE_KAFKA_FOR_PATCH") // ensure it's not set

		result := getEnvAsBool("USE_KAFKA_FOR_PATCH", false)
		assert.False(t, result) // should return default (false)
	})
}
