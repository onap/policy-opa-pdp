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

package astgenerator

import (
    "bytes"
    "errors"
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "policy-opa-pdp/consts"
    "policy-opa-pdp/pkg/log"
    "runtime"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
    // Silence logger during tests to avoid false positives in go test
    log.Log.Logger.SetOutput(io.Discard)
    os.Exit(m.Run())
}

// setupPaths configures temporary paths for tests and returns a cleanup function.
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
        if err == nil {
            log.Log.Logger.SetOutput(io.Discard)
            logFile.Close() // Fix file lock issue
        }
        consts.TempRegoFolderPath = originalTempFolderPath
        consts.LogFilePath = originalLogFilePath
        // No need to remove tempDir as t.TempDir() handles it
    }
}

// setupMockOpa configures a dummy "opa" executable and overrides consts.Opa.
func setupMockOpa(t testing.TB, output string) {
    tempDir := t.TempDir()

    var scriptContent string
    var scriptName string
    if runtime.GOOS == "windows" {
        scriptName = "opa.bat"
        scriptContent = fmt.Sprintf("@echo off\necho %s\n", output)
    } else {
        scriptName = "opa"
        scriptContent = fmt.Sprintf("#!/bin/sh\necho '%s'\n", output)
    }

    mockOpaPath := filepath.Join(tempDir, scriptName)
    err := os.WriteFile(mockOpaPath, []byte(scriptContent), 0755)
    assert.NoError(t, err)

    originalOpa := consts.Opa
    consts.Opa = mockOpaPath
    t.Cleanup(func() { consts.Opa = originalOpa })
}

// mockResponseWriter is a http.ResponseWriter that fails on Write
type mockResponseWriter struct {
    *httptest.ResponseRecorder
    failWrite bool
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
    if m.failWrite {
        return 0, errors.New("write error")
    }
    return m.ResponseRecorder.Write(b)
}

func TestASTGeneratorHandler_MethodNotAllowed(t *testing.T) {
    defer setupPaths(t)()
    req := httptest.NewRequest(http.MethodGet, "/ast", nil)
    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
    assert.Contains(t, w.Body.String(), "use POST")
}

func TestASTGeneratorHandler_InvalidJSON(t *testing.T) {
    defer setupPaths(t)()
    body := bytes.NewBufferString("{ invalid json }")

    req := httptest.NewRequest(http.MethodPost, "/ast", body)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusBadRequest, w.Code)
    assert.Contains(t, w.Body.String(), "invalid JSON")
}

func TestASTGeneratorHandler_EmptyCode(t *testing.T) {
    defer setupPaths(t)()
    body := bytes.NewBufferString(`{"code": ""}`)

    req := httptest.NewRequest(http.MethodPost, "/ast", body)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusBadRequest, w.Code)
    assert.Contains(t, w.Body.String(), "code is required")
}


func TestASTGeneratorHandler_ParseASTError(t *testing.T) {
    defer setupPaths(t)()

    // Creating a mock OPA executable which fails for mimic-ing a parse error
    setupMockOpa(t, "parse error dummy")

    body := bytes.NewBufferString(`{
"code": "this is invalid rego code"
}`)
    req := httptest.NewRequest(http.MethodPost, "/ast", body)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusBadRequest, w.Code)
    assert.Contains(t, w.Body.String(), "error")
}

func TestASTGeneratorHandler_Success(t *testing.T) {
    defer setupPaths(t)()

    // Mock success outcome via PATH hijacking
    setupMockOpa(t, `{"ast": "mocked ast"}`)

    body := bytes.NewBufferString(`{"code": "package test"}`)
    req := httptest.NewRequest(http.MethodPost, "/ast", body)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
    assert.Contains(t, w.Body.String(), "mocked ast")
}

func TestASTGeneratorHandler_UnmarshalError(t *testing.T) {
    defer setupPaths(t)()

    // Mock success but with invalid format (array instead of map)
    setupMockOpa(t, `[]`)

    body := bytes.NewBufferString(`{"code": "package test"}`)
    req := httptest.NewRequest(http.MethodPost, "/ast", body)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusBadRequest, w.Code)
    assert.Contains(t, w.Body.String(), "invalid JSON")
}

func TestASTGeneratorHandler_EncodeError(t *testing.T) {
    defer setupPaths(t)()
    log.Log.Logger.SetOutput(io.Discard)

    setupMockOpa(t, `{"ast": "mocked"}`)

    body := bytes.NewBufferString(`{"code": "package test"}`)
    req := httptest.NewRequest(http.MethodPost, "/ast", body)
    req.Header.Set("Content-Type", "application/json")

    recorder := httptest.NewRecorder()
    w := &mockResponseWriter{ResponseRecorder: recorder, failWrite: true}

    ASTGeneratorHandler(w, req)

    assert.Empty(t, recorder.Body.Bytes())
}
