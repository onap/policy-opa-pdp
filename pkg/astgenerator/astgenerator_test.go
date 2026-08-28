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
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"testing"
)

func TestMain(m *testing.M) {
	// Silence logger during tests to avoid false positives in go test
	log.Log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// setupPaths configures temporary paths for tests and returns a cleanup function.
func setupPaths(t testing.TB) func() {
	originalLogFilePath := consts.LogFilePath

	tempDir := t.TempDir()
	consts.LogFilePath = filepath.Join(tempDir, "test.log")

	// Redirect logger to the temp file
	logFile, err := os.Create(consts.LogFilePath)
	if err == nil {
		log.Log.SetOutput(logFile)
	}

	return func() {
		if err == nil {
			log.Log.SetOutput(io.Discard)
			_ = logFile.Close() // Fix file lock issue
		}
		consts.LogFilePath = originalLogFilePath
		// No need to remove tempDir as t.TempDir() handles it
	}
}

// stubParseAST replaces the parser seam so the handler's error branches can be reached
// without feeding the real parser input it would never produce.
func stubParseAST(t testing.TB, astJSON json.RawMessage, err error) {
	original := parseASTVar
	parseASTVar = func(string) (json.RawMessage, error) { return astJSON, err }
	t.Cleanup(func() { parseASTVar = original })
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

	body := bytes.NewBufferString(`{
"code": "this is invalid rego code"
}`)
	req := httptest.NewRequest(http.MethodPost, "/ast", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	ASTGeneratorHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "failed to parse policy")
}

func TestASTGeneratorHandler_Success(t *testing.T) {
	defer setupPaths(t)()

	body := bytes.NewBufferString(`{"code": "package test\n\nallow := true\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/ast", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	ASTGeneratorHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"package"`)
	assert.Contains(t, w.Body.String(), "allow")
}

func TestASTGeneratorHandler_UnmarshalError(t *testing.T) {
	defer setupPaths(t)()

	// A JSON array cannot be unmarshalled into the response's map-typed Ast field.
	stubParseAST(t, json.RawMessage(`[]`), nil)

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
	log.Log.SetOutput(io.Discard)

	body := bytes.NewBufferString(`{"code": "package test"}`)
	req := httptest.NewRequest(http.MethodPost, "/ast", body)
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	w := &mockResponseWriter{ResponseRecorder: recorder, failWrite: true}

	ASTGeneratorHandler(w, req)

	assert.Empty(t, recorder.Body.Bytes())
}
