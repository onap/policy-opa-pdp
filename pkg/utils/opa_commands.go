// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2026: Deutsche Telekom
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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"regexp"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

// createTempFile creates a temporary file with given content and returns the file path and cleanup function
func createTempFile(prefix, content string) (string, func(), error) {
	tmpFile, err := os.CreateTemp(consts.TempRegoFolderPath, prefix)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	log.Debugf("Temp file %s is written with %s", tmpFile.Name(), content)
	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		return "", nil, fmt.Errorf("failed to write temp file: %v", err)
	}
	tmpFile.Close()
	cleanup := func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			log.Warnf("Failed to remove temp file %s: %v", tmpFile.Name(), err)
		} else {
			log.Debugf("Temp file %s removed successfully", tmpFile.Name())
		}
		log.Debugf("Temp file %s removed successfully", tmpFile.Name())
	}
	return tmpFile.Name(), cleanup, nil
}

// runOPACommand runs an OPA exec.Cmd and cleanly handles stdout/stderr capture and logging.
// It returns stdout, stderr, and any run error.
func runOPACommand(cmd *exec.Cmd, context string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	outStr := stdout.String()
	errStr := stderr.String()
	if err != nil {
		// Log both stdout and stderr with context
		log.Errorf("%s failed:\nSTDOUT:\n%s\nSTDERR:\n%s", context, outStr, errStr)
	}
	return outStr, errStr, err
}

// ParseAST runs `opa parse --format=json` on the provided regoCode and returns the AST.
func ParseAST(cmdFunc func(string, ...string) *exec.Cmd, regoCode string) (json.RawMessage, error) {
	log.Debugf("ParseAST input (truncated): %.128s", regoCode)

	// Write to a temp file to keep behavior deterministic across environments
	regoFilePath, cleanup, err := createTempFile(consts.TempRegoPattern, regoCode)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Build and run: opa parse --format=json <temp.rego>
	cmd := cmdFunc(consts.Opa, "parse", "--format=json", regoFilePath)
	stdoutStr, stderrStr, runErr := runOPACommand(cmd, "OPA Parse")

	if runErr != nil {
		// Normalize error message, replacing temp path with a standard name to avoid leaking internals
		var cleanMsg string
		switch {
		case stderrStr != "":
			cleanMsg = stderrStr
		case stdoutStr != "":
			cleanMsg = stdoutStr
		default:
			cleanMsg = "OPA parse failed with unknown error"
		}
		re := regexp.MustCompile(consts.TempPolicyFileRegex)
		cleanMsg = re.ReplaceAllString(cleanMsg, consts.StandardPolicyName)
		return nil, fmt.Errorf("failed to parse policy: %s", cleanMsg)
	}

	// Validate that stdout is valid JSON and return it
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(stdoutStr), &raw); err != nil {
		return nil, fmt.Errorf("OPA output was not valid JSON: %w", err)
	}

	return raw, nil
}
