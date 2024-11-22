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

// Package cfg provides configuration settings for the policy-opa-pdp service.
// This package includes variables for various configuration settings such as log level,
// Kafka server details, and credentials.It also includes functions to initialize these
// settings and retrieve environment variables with default values.
package cfg

import (
	log "github.com/sirupsen/logrus"
	"os"
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
	LogLevel        string
	BootstrapServer string
	Topic           string
	GroupId         string
	Username        string
	Password        string
	UseSASLForKAFKA string
	KAFKA_USERNAME  string
	KAFKA_PASSWORD  string
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
	GroupId = getEnv("GROUPID", "opa-pdp")
	Username = getEnv("API_USER", "policyadmin")
	Password = getEnv("API_PASSWORD", "zb!XztG34")
	UseSASLForKAFKA = getEnv("UseSASLForKAFKA", "false")
	KAFKA_USERNAME = getEnv("KAFKA_USERNAME", "strimzi-kafka-user")
	KAFKA_PASSWORD = getEnv("KAFKA_PASSWORD", "kafkaSecretPassword123")
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

// Retrieves the value of an environment variable as an integer or returns a default value if not set.
func getEnvAsInt(name string, defaultVal int) int {
	valueStr := getEnv(name, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	} else if valueStr != "" {
		log.Warnf("Invalid int value: %v for variable: %v. Default value: %v will be used", valueStr, name, defaultVal)
	}

	return defaultVal
}

// Retrieves the log level from an environment variable or returns a default value if not set.
func getLogLevel(key string, defaultVal string) log.Level {
	logLevelStr := getEnv(key, defaultVal)
	if loglevel, err := log.ParseLevel(logLevelStr); err == nil {
		return loglevel
	} else {
		log.Warnf("Invalid log level: %v. Log level will be Info!", logLevelStr)
		return log.DebugLevel
	}
}
