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
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"
	"strconv"
)

// The environment variable each of these is read from, its default and its meaning are
// documented in the configuration table in README.md. That table is the operator-facing
// contract; duplicating it here is what let the previous comment block drift out of date.
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
	AllowTracing     bool
)

// Initializes the configuration settings.
func init() {

	log.SetOutput(os.Stdout)

	// The level has to be resolved and applied before the remaining variables are read.
	// Reading them emits one message per defaulted value, and at the default logrus level
	// a correctly configured startup drowned in them.
	LogLevel = getEnv("LOG_LEVEL", "info")
	if level, err := log.ParseLevel(LogLevel); err != nil {
		log.SetLevel(log.InfoLevel)
		log.Warnf("Invalid LOG_LEVEL %q, using info", LogLevel)
	} else {
		log.SetLevel(level)
	}

	log.Debug("###################################### ")
	log.Debug("OPA-PDP: Starting initialisation ")
	log.Debug("###################################### ")

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
	AllowTracing = getEnvAsBool("ALLOW_TRACING", false)
	log.Debug("Configuration module: environment initialised")
}

// Retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	log.Debugf("%v not defined, using default value", key)
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
	log.Debugf("%v not defined, using default value: %v", key, defaultVal)
	return defaultVal
}

// Validate reports every problem with the resolved configuration at once, so an operator
// fixing a deployment sees the whole list rather than one problem per restart.
//
// Everything checked here is a misconfiguration that no amount of retrying fixes, and each
// one otherwise surfaces much later and far from its cause: an empty API_PASSWORD makes
// validateCredentials reject every request, so the PDP keeps deploying policies over Kafka
// while answering 401 to every decision.
func Validate() error {
	var problems []error

	for _, required := range []struct{ name, value string }{
		{"API_USER", Username},
		{"API_PASSWORD", Password},
		{"KAFKA_URL", BootstrapServer},
		{"PAP_TOPIC", Topic},
		{"PATCH_TOPIC", PatchTopic},
		{"GROUPID", GroupId},
		{"PATCH_GROUPID", PatchGroupId},
	} {
		if required.value == "" {
			problems = append(problems, fmt.Errorf("%s must not be empty", required.name))
		}
	}

	problems = append(problems, validateBootstrapServer()...)

	// The Kafka clients compare this against the literal "true", so "True" or "1" would
	// silently disable SASL and then fail at connect time as an authentication error.
	switch UseSASLForKAFKA {
	case "true":
		if KAFKA_USERNAME == "" || KAFKA_PASSWORD == "" {
			problems = append(problems, errors.New(
				"UseSASLForKAFKA is true but no credentials were parsed from JAASLOGIN"))
		}
	case "false":
	default:
		problems = append(problems, fmt.Errorf(
			"UseSASLForKAFKA must be exactly \"true\" or \"false\", got %q", UseSASLForKAFKA))
	}

	return errors.Join(problems...)
}

func validateBootstrapServer() []error {
	if BootstrapServer == "" {
		return nil
	}

	var problems []error
	for _, broker := range strings.Split(BootstrapServer, ",") {
		broker = strings.TrimSpace(broker)
		if strings.Contains(broker, "://") {
			problems = append(problems, fmt.Errorf(
				"KAFKA_URL entry %q must be host:port, without a scheme", broker))
			continue
		}

		_, port, err := net.SplitHostPort(broker)
		if err != nil {
			problems = append(problems, fmt.Errorf("KAFKA_URL entry %q must be host:port: %w", broker, err))
			continue
		}
		if parsed, err := strconv.Atoi(port); err != nil || parsed < 1 || parsed > 65535 {
			problems = append(problems, fmt.Errorf("KAFKA_URL entry %q has an invalid port %q", broker, port))
		}
	}
	return problems
}

// Summary renders the resolved configuration for a single startup log line. Credentials are
// reported as set or unset rather than printed.
func Summary() string {
	return fmt.Sprintf("LOG_LEVEL=%s KAFKA_URL=%s PAP_TOPIC=%s PATCH_TOPIC=%s GROUPID=%s "+
		"PATCH_GROUPID=%s API_USER=%s API_PASSWORD=%s UseSASLForKAFKA=%s JAASLOGIN=%s "+
		"USE_KAFKA_FOR_PATCH=%t ALLOW_TRACING=%t",
		LogLevel, BootstrapServer, Topic, PatchTopic, GroupId, PatchGroupId,
		Username, redacted(Password), UseSASLForKAFKA, redacted(KAFKA_PASSWORD),
		UseKafkaForPatch, AllowTracing)
}

func redacted(value string) string {
	if value == "" {
		return "<unset>"
	}
	return "<set>"
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
