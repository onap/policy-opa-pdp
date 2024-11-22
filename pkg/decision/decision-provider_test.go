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
//

package decision

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/pdpstate"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpaDecision_MethodNotAllowed(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Contains(t, rec.Body.String(), "MethodNotAllowed")
}

func TestOpaDecision_InvalidJSON(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte("invalid json")))
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpaDecision_MissingPolicyPath(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	body := map[string]interface{}{"onapName": "CDS", "onapComponent": "CDS", "onapInstance": "CDS", "requestId": "8e6f784e-c9cb-42f6-bcc9-edb5d0af1ce1", "input": nil}

	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonBody))
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Policy used to make decision is nil")
}

func TestOpaDecision_GetInstanceError(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	body := map[string]interface{}{"policy": "data.policy"}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonBody))
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpaDecision_OPADecisionError(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Active
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	body := map[string]interface{}{"policy": "data.policy"}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(jsonBody))
	rec := httptest.NewRecorder()

	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	consts.OpasdkConfigPath = tmpFile.Name()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpaDecision_PassiveState(t *testing.T) {
	originalGetState := pdpstate.GetCurrentState
	pdpstate.GetCurrentState = func() model.PdpState {
		return model.Passive
	}
	defer func() { pdpstate.GetCurrentState = originalGetState }()
	req := httptest.NewRequest(http.MethodPost, "/opa/decision", nil)
	rec := httptest.NewRecorder()

	OpaDecision(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), " System Is In PASSIVE State")
}
