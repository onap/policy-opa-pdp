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
    "net/http"
    "net/http/httptest"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestASTGeneratorHandler_MethodNotAllowed(t *testing.T) {
    req := httptest.NewRequest(http.MethodGet, "/ast", nil)
    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
    assert.Contains(t, w.Body.String(), "use POST")
}

func TestASTGeneratorHandler_InvalidJSON(t *testing.T) {
    body := bytes.NewBufferString("{ invalid json }")

    req := httptest.NewRequest(http.MethodPost, "/ast", body)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusBadRequest, w.Code)
    assert.Contains(t, w.Body.String(), "invalid JSON")
}

func TestASTGeneratorHandler_EmptyCode(t *testing.T) {
    body := bytes.NewBufferString(`{"code": ""}`)

    req := httptest.NewRequest(http.MethodPost, "/ast", body)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()

    ASTGeneratorHandler(w, req)

    assert.Equal(t, http.StatusBadRequest, w.Code)
    assert.Contains(t, w.Body.String(), "code is required")
}


func TestASTGeneratorHandler_ParseASTError(t *testing.T) {
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
