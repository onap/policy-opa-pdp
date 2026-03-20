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

// Package astgenerator provides a REST handler that parses Rego code
// and returns the AST as JSON using OPA v1 AST APIs.
package astgenerator

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"policy-opa-pdp/pkg/log"
	model "policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/utils"
)

func writeErrorResponse(w http.ResponseWriter, status int, msg string, code model.ErrorResponseResponseCode) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(model.GenericErrorResponse{
		ErrorMessage: &msg,
		ResponseCode: &code,
	})
}

func ASTGeneratorHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("[astgenerator] starting AST generation")

	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "use POST Method", model.InvalidOperation)
		return
	}

	var req model.OPAASTGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err), model.BadRequest)
		return
	}

	if req.Code == nil || *req.Code == "" {
		writeErrorResponse(w, http.StatusBadRequest, "code is required for ast generation", model.InvalidParameter)
		return
	}

	var cmdFunc = func(name string, args ...string) *exec.Cmd {
		return exec.Command(name, args...)
	}

	// Call the CLI-backed parser to get AST as JSON
	astJSON, err := utils.ParseAST(cmdFunc, *req.Code)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, err.Error(), model.EvaluationError)
		return
	}

	// Populate response struct
	var res model.OPAASTGenerateResponse
	res.Ast = &map[string]interface{}{}
	if err := json.Unmarshal(astJSON, res.Ast); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err), model.BadRequest)
		return
	}

	// Success response
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode response: %v", err), model.InternalError)
		return
	}
}
