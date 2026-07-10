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

// Package cfg provides configuration settings for the policy-opa-pdp service.
// This package includes variables for various configuration settings such as log level,
// Kafka server details, and credentials.It also includes functions to initialize these
// settings and retrieve environment variables with default values.
package cfg

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"
	"strconv"
)

// LogLevel        - The log level for the application.
// BootstrapServer - The Kafka bootstrap server address.
// Topic           - The Kafka topic to subscribe to.
// GroupId         - The Kafka consumer group ID.
// Username        - The username for basic authentication.
// Password        - The password for basic authentication.
// UseSASLForKAFKA - Flag to indicate if SASL should be used for Kafka.
// KAFKA_USERNAME  - The Kafka username for SASL authentication.
// KAFKA_PASSWORD  - The Kafka password for SASL authentication.
var (
	LogLevel         string
	BootstrapServer  string
	Topic            string
	PatchTopic       string
	GroupId          string
	Username         string
	Password         string
	UseSASLForKAFKA  string
	KAFKA_USERNAME   string
	KAFKA_PASSWORD   string
	JAASLOGIN        string
	UseKafkaForPatch bool
	PatchGroupId     string
)

// Initializes the configuration settings.
func init() {

	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)

	log.Debug("###################################### ")
	log.Debug("OPA-PDP: Starting initialisation ")
	log.Debug("###################################### ")

	LogLevel = getEnv("LOG_LEVEL", "info")
	BootstrapServer = getEnv("KAFKA_URL", "kafka:9092")
	Topic = getEnv("PAP_TOPIC", "policy-pdp-pap")
	PatchTopic = getEnv("PATCH_TOPIC", "opa-pdp-data")
	GroupId = getEnv("GROUPID", "opa-pdp-"+uuid.New().String())
	PatchGroupId = getEnv("PATCH_GROUPID", "opa-pdp-data-"+uuid.New().String())
	Username = getEnv("API_USER", "policyadmin")
	Password = getEnv("API_PASSWORD", "")
	UseSASLForKAFKA = getEnv("UseSASLForKAFKA", "false")
	KAFKA_USERNAME, KAFKA_PASSWORD = getSaslJAASLOGINFromEnv()
	UseKafkaForPatch = getEnvAsBool("USE_KAFKA_FOR_PATCH", false)
	log.Debug("Configuration module: environment initialised")
}

// Retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	log.Warnf("%v not defined, using default value", key)
	return defaultVal
}

func getEnvAsBool(key string, defaultVal bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			log.Warnf("%v is set but not a valid bool (%v), using default: %v", key, value, defaultVal)
			return defaultVal
		}
		return parsed
	}
	log.Warnf("%v not defined, using default value: %v", key, defaultVal)
	return defaultVal
}

func getSaslJAASLOGINFromEnv() (string, string) {
	config := getEnv("JAASLOGIN", "")
	if config == "" {
		return "", ""
	}

	// Extract username and password using regex
	usernamePattern := `username=["'](.+?)["']`
	passwordPattern := `password=["'](.+?)["']`

	// Extract username
	usernameMatch := regexp.MustCompile(usernamePattern).FindStringSubmatch(config)
	if len(usernameMatch) < 2 {
		return "", ""
	}
	username := usernameMatch[1]

	// Extract password
	passwordMatch := regexp.MustCompile(passwordPattern).FindStringSubmatch(config)
	if len(passwordMatch) < 2 {
		return "", ""
	}
	password := passwordMatch[1]

	return username, password
}
