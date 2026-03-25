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
	"os"
	"os/exec"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupPaths(t testing.TB) func() {
	originalTempFolderPath := consts.TempRegoFolderPath
	originalLogFilePath := consts.LogFilePath

	tempDir := t.TempDir()
	consts.TempRegoFolderPath = tempDir + string(os.PathSeparator)
	consts.LogFilePath = filepath.Join(tempDir, "test.log")

	// Redirect logger to the temp file
	logFile, err := os.Create(consts.LogFilePath)
	if err == nil {
		log.Log.Logger.SetOutput(logFile)
	}

	return func() {
		consts.TempRegoFolderPath = originalTempFolderPath
		consts.LogFilePath = originalLogFilePath
	}
}

func TestCreateTempFile(t *testing.T) {
	defer setupPaths(t)()
	t.Run("Creates temp file successfully", func(t *testing.T) {
		content := "test content"
		filePath, cleanup, err := createTempFile("policy*.rego", content)

		// Assertions
		assert.NoError(t, err)
		assert.NotEmpty(t, filePath)
		assert.NotNil(t, cleanup)

		// Check file exists and content matches
		data, readErr := os.ReadFile(filePath)
		assert.NoError(t, readErr)
		assert.Equal(t, content, string(data))

		// Cleanup should remove file
		cleanup()
		_, statErr := os.Stat(filePath)
		assert.True(t, os.IsNotExist(statErr))
	})
}

func TestCreateTempFile_Failure(t *testing.T) {
	// Don't call setupPaths as we want to intentionally set a bad path
	originalTempFolderPath := consts.TempRegoFolderPath
	defer func() { consts.TempRegoFolderPath = originalTempFolderPath }()

	// Use a path that is actually a file, not a directory.
	// os.CreateTemp will fail on this.
	tmpFile, _ := os.CreateTemp("", "bad-dir-*")
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	consts.TempRegoFolderPath = tmpFile.Name()

	filePath, cleanup, err := createTempFile("policy*.rego", "content")
	assert.Error(t, err)
	assert.Empty(t, filePath)
	assert.Nil(t, cleanup)
	assert.Contains(t, err.Error(), "failed to create temp file")
}

func TestRunOPACommand_Success(t *testing.T) {
	defer setupPaths(t)()
	// On Windows, use 'cmd /c echo' instead of 'echo' if needed, but 'echo' usually works.
	// However, to be safe and avoid external dependencies in runOPACommand success,
	// we use a simple command that exists on most systems.
	cmd := exec.Command("echo", "hello")
	stdout, stderr, err := runOPACommand(cmd, "Test Context")

	assert.NoError(t, err)
	assert.Contains(t, stdout, "hello")
	assert.Empty(t, stderr)
}

func TestRunOPACommand_Failure(t *testing.T) {
	defer setupPaths(t)()
	// Use a command that definitely fails
	cmd := exec.Command("false")
	if _, err := exec.LookPath("false"); err != nil {
		// on Windows, 'false' might not exist, use a non-existent command
		cmd = exec.Command("non-existent-command")
	}

	stdout, _, err := runOPACommand(cmd, "Test Context")

	assert.Error(t, err)
	assert.Empty(t, stdout)
}

// TestParseAST tests the ParseAST function using a mocked OPA command.
func TestParseAST(t *testing.T) {
	defer setupPaths(t)()

	t.Run("Success", func(t *testing.T) {
		mockCmdFunc := func(command string, args ...string) *exec.Cmd {
			mockOutput := `{"ast": "mocked ast"}`
			if runtime.GOOS == "windows" {
				return exec.Command("cmd", "/c", "echo "+mockOutput)
			}
			return exec.Command("sh", "-c", "echo '"+mockOutput+"'")
		}
		result, err := ParseAST(mockCmdFunc, "package test")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Contains(t, string(result), "mocked ast")
	})

	t.Run("Failure - OPA Error Stderr Only", func(t *testing.T) {
		mockCmdFunc := func(command string, args ...string) *exec.Cmd {
			// Mock failure with stderr output but no stdout
			msg := "error in stderr"
			if runtime.GOOS == "windows" {
				return exec.Command("cmd", "/c", "echo "+msg+" 1>&2 && exit 1")
			}
			return exec.Command("sh", "-c", "echo '"+msg+"' 1>&2; exit 1")
		}
		result, err := ParseAST(mockCmdFunc, "package test")
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "error in stderr")
	})

	t.Run("Failure - OPA Error Stdout Only", func(t *testing.T) {
		mockCmdFunc := func(command string, args ...string) *exec.Cmd {
			// Mock failure with stdout output but no stderr
			msg := "error in stdout"
			if runtime.GOOS == "windows" {
				return exec.Command("cmd", "/c", "echo "+msg+" && exit 1")
			}
			return exec.Command("sh", "-c", "echo '"+msg+"'; exit 1")
		}
		result, err := ParseAST(mockCmdFunc, "package test")
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "error in stdout")
	})

	t.Run("Failure - OPA Error No Output", func(t *testing.T) {
		mockCmdFunc := func(command string, args ...string) *exec.Cmd {
			// Mock failure with no stdout/stderr output (e.g. exit 1)
			if runtime.GOOS == "windows" {
				return exec.Command("cmd", "/c", "exit 1")
			}
			return exec.Command("sh", "-c", "exit 1")
		}
		result, err := ParseAST(mockCmdFunc, "package test")
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to parse policy: OPA parse failed with unknown error")
	})

	t.Run("Failure - OPA Error Stdout Only", func(t *testing.T) {
		mockCmdFunc := func(command string, args ...string) *exec.Cmd {
			// Mock failure with stdout output but no stderr
			msg := "error in stdout"
			if runtime.GOOS == "windows" {
				return exec.Command("cmd", "/c", "echo "+msg+" && exit 1")
			}
			return exec.Command("sh", "-c", "echo '"+msg+"'; exit 1")
		}
		result, err := ParseAST(mockCmdFunc, "package test")
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "error in stdout")
	})

	t.Run("Failure - CreateTempFile", func(t *testing.T) {
		// Use a path that is actually a file, not a directory.
		tmpFile, _ := os.CreateTemp("", "bad-dir-*")
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		originalPath := consts.TempRegoFolderPath
		consts.TempRegoFolderPath = tmpFile.Name()
		defer func() { consts.TempRegoFolderPath = originalPath }()

		result, err := ParseAST(nil, "package test")
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("Failure - Invalid JSON from OPA", func(t *testing.T) {
		mockCmdFunc := func(command string, args ...string) *exec.Cmd {
			mockOutput := "not json"
			if runtime.GOOS == "windows" {
				return exec.Command("cmd", "/c", "echo "+mockOutput)
			}
			return exec.Command("sh", "-c", "echo '"+mockOutput+"'")
		}
		result, err := ParseAST(mockCmdFunc, "INVALID_JSON")
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "OPA output was not valid JSON")
	})
}
