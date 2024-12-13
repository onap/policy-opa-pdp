// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024: Deutsche Telekom
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

// Package decision provides functionalities for handling decision requests using OPA (Open Policy Agent).
// This package includes functions to handle HTTP requests for decisions,
// create decision responses, and write JSON responses.
package decision

import (
	"context"
	"encoding/json"
	"net/http"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/pdpstate"
	"policy-opa-pdp/pkg/utils"
	"strings"
        "fmt"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/open-policy-agent/opa/sdk"
)

// creates a response code map to ErrorResponseResponseCode
var httpToResponseCode = map[int]oapicodegen.ErrorResponseResponseCode{
	400: oapicodegen.BADREQUEST,
	401: oapicodegen.UNAUTHORIZED,
	500: oapicodegen.INTERNALSERVERERROR,
}

// Gets responsecode from map
func GetErrorResponseResponseCode(httpStatus int) oapicodegen.ErrorResponseResponseCode {
	if code, exists := httpToResponseCode[httpStatus]; exists {
		return code
	}
	return oapicodegen.INTERNALSERVERERROR
}

// writes a Successful  JSON response to the HTTP response writer
func writeOpaJSONResponse(res http.ResponseWriter, status int, decisionRes oapicodegen.OPADecisionResponse) {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(status)
	if err := json.NewEncoder(res).Encode(decisionRes); err != nil {
		http.Error(res, err.Error(), status)
	}
}

// writes a Successful  JSON response to the HTTP response writer
func writeErrorJSONResponse(res http.ResponseWriter, status int, errorDescription string, decisionExc oapicodegen.ErrorResponse) {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(status)
	if err := json.NewEncoder(res).Encode(decisionExc); err != nil {
		http.Error(res, err.Error(), status)
	}
}

// creates a decision response based on the provided parameters
func createSuccessDecisionResponse(statusMessage, decision, policyName string, output map[string]interface{}) *oapicodegen.OPADecisionResponse {
	return &oapicodegen.OPADecisionResponse{
		StatusMessage: &statusMessage,
		Decision:      (*oapicodegen.OPADecisionResponseDecision)(&decision),
		PolicyName:    &policyName,
		Output:        &output,
	}
}

// creates a decision response based on the provided parameters
func createDecisionExceptionResponse(statusCode int, errorMessage string, errorDetails []string, policyName string) *oapicodegen.ErrorResponse {
	responseCode := GetErrorResponseResponseCode(statusCode)
	return &oapicodegen.ErrorResponse{
		ResponseCode: (*oapicodegen.ErrorResponseResponseCode)(&responseCode),
		ErrorMessage: &errorMessage,
		ErrorDetails: &errorDetails,
		PolicyName:   &policyName,
	}
}

// handles HTTP requests for decisions using OPA.
func OpaDecision(res http.ResponseWriter, req *http.Request) {
	log.Debugf("PDP received a decision request.")

	requestId := req.Header.Get("X-ONAP-RequestID")
	var parsedUUID *uuid.UUID
	var decisionParams *oapicodegen.DecisionParams
	var err error

	if requestId != "" && utils.IsValidUUID(requestId) {
		tempUUID, err := uuid.Parse(requestId)
		if err != nil {
			log.Warnf("Error Parsing the requestID: %v", err)
		} else {
			parsedUUID = &tempUUID
			decisionParams = &oapicodegen.DecisionParams{
				XONAPRequestID: (*openapi_types.UUID)(parsedUUID),
			}
			res.Header().Set("X-ONAP-RequestID", decisionParams.XONAPRequestID.String())
		}
	} else {
		requestId = "Unknown"
		res.Header().Set("X-ONAP-RequestID", requestId)
	}

	res.Header().Set("X-LatestVersion", consts.LatestVersion)
	res.Header().Set("X-PatchVersion", consts.PatchVersion)
	res.Header().Set("X-MinorVersion", consts.MinorVersion)

	log.Debugf("Headers..")
	for key, value := range res.Header() {
		log.Debugf("%s: %s", key, value)
	}
	// Check if the system is in an active state
	if pdpstate.GetCurrentState() != model.Active {
		msg := " System Is In PASSIVE State so Unable To Handle Decision wait until it becomes ACTIVE"
		errorMsg := " System Is In PASSIVE State so error Handling the request"
		decisionExc := createDecisionExceptionResponse(http.StatusInternalServerError, msg, []string{errorMsg}, "")
		metrics.IncrementTotalErrorCount()
		writeErrorJSONResponse(res, http.StatusInternalServerError, msg, *decisionExc)
		return
	}
	ctx := context.Background()

	// Check if the request method is POST
	if req.Method != http.MethodPost {
		msg := " MethodNotAllowed"
		decisionExc := createDecisionExceptionResponse(http.StatusMethodNotAllowed, "Only POST Method Allowed",
			[]string{req.Method + msg}, "")
		metrics.IncrementTotalErrorCount()
		writeErrorJSONResponse(res, http.StatusMethodNotAllowed, req.Method+msg, *decisionExc)
		return
	}

	var decisionReq oapicodegen.OPADecisionRequest

	// Decode the request body into a DecisionRequest struct
	if err := json.NewDecoder(req.Body).Decode(&decisionReq); err != nil {
		decisionExc := createDecisionExceptionResponse(http.StatusBadRequest, "Error decoding the request",
			[]string{err.Error()}, "")
		metrics.IncrementTotalErrorCount()
		writeErrorJSONResponse(res, http.StatusBadRequest, err.Error(), *decisionExc)
		return
	}

	// Check if the policy is provided in the request
	if decisionReq.PolicyName == nil || *decisionReq.PolicyName == "" {
		msg := "Policy used to make decision is nil"
		decisionExc := createDecisionExceptionResponse(http.StatusBadRequest, "policy details not provided",
			[]string{msg}, "")
		metrics.IncrementTotalErrorCount()
		writeErrorJSONResponse(res, http.StatusBadRequest, msg, *decisionExc)
		return
	}

	// Get the OPA singleton instance
	opa, err := opasdk.GetOPASingletonInstance()
	if err != nil {
		msg := "Failed to get OPA instance"
		log.Warnf("Failed to get OPA instance: %s", err)
		decisionExc := createDecisionExceptionResponse(http.StatusInternalServerError, "OPA instance creation error", []string{msg},
			*decisionReq.PolicyName)
		metrics.IncrementTotalErrorCount()
		writeErrorJSONResponse(res, http.StatusInternalServerError, msg, *decisionExc)
		return
	}

	log.Debugf("SDK making a decision")
	options := sdk.DecisionOptions{Path: *decisionReq.PolicyName, Input: decisionReq.Input}

	decision, err := opa.Decision(ctx, options)

	jsonOutput, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		log.Warnf("Error serializing decision output: %v\n", err)
		return
	}
	log.Debugf("RAW opa Decision output:\n%s\n", string(jsonOutput))

	// Check for errors in the OPA decision
	if err != nil {
		if strings.Contains(err.Error(), "opa_undefined_error") {
			decisionRes := createSuccessDecisionResponse(err.Error(), string(oapicodegen.INDETERMINATE),
				*decisionReq.PolicyName, nil)
			writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
			metrics.IncrementIndeterminantDecisionsCount()
			return
		} else {
			decisionExc := createDecisionExceptionResponse(http.StatusBadRequest, "Error from OPA while making decision",
				[]string{err.Error()}, *decisionReq.PolicyName)
			metrics.IncrementTotalErrorCount()
			writeErrorJSONResponse(res, http.StatusBadRequest, err.Error(), *decisionExc)
			return
		}
	}

	var policyFilter []string
	if decisionReq.PolicyFilter != nil {
		policyFilter = *decisionReq.PolicyFilter
	}

	// Decision Result Processing
	outputMap := make(map[string]interface{})
	// Check if the decision result is a bool or a map
	switch result := decision.Result.(type) {
	case bool:
		// If the result is a boolean (true/false)
		if result {
			// If "allow" is true, process filters if they exist
			if len(policyFilter) > 0 {
				// If filters are present, we apply them
				decisionRes := createSuccessDecisionResponse("OPA Allowed", string(oapicodegen.PERMIT), *decisionReq.PolicyName, nil)
				metrics.IncrementPermitDecisionsCount()
				writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
				return
			}

			// No filters provided, just allow the decision
			decisionRes := createSuccessDecisionResponse("OPA Allowed", string(oapicodegen.PERMIT), *decisionReq.PolicyName, nil)
			metrics.IncrementPermitDecisionsCount()
			writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
			return
		}

		// If "allow" is false
		decisionRes := createSuccessDecisionResponse("OPA Denied", string(oapicodegen.DENY), *decisionReq.PolicyName, nil)
		metrics.IncrementDenyDecisionsCount()
		writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
		return

	case map[string]interface{}:
		if len(policyFilter) > 0 {
			// Apply the policy filter if present
			filteredResult := applyPolicyFilter(result, policyFilter)
			if filteredResultMap, ok := filteredResult.(map[string]interface{}); ok && len(filteredResultMap) > 0 {
				outputMap = filteredResultMap
			} else {
				decisionRes := createSuccessDecisionResponse(
					"No Decision: Result is Empty after applying filter",
					string(oapicodegen.NOTAPPLICABLE),
					*decisionReq.PolicyName, nil)
				metrics.IncrementQueryFailureCount()
				writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
				return
			}
		} else {
			// Process result without filters
			var statusMessage string
			boolValueFound := false
			for key, value := range result {
				if len(statusMessage) == 0 {
					statusMessage = fmt.Sprintf("%s: %v", key, value)
				} else {
					statusMessage = fmt.Sprintf("%s ,%s: %v", statusMessage, key, value)
				}
				if boolVal, ok := value.(bool); ok {
					boolValueFound = boolVal
				}
			}
			// Return decision based on boolean value
			if boolValueFound {
				decisionRes := createSuccessDecisionResponse(statusMessage, string(oapicodegen.PERMIT),
					*decisionReq.PolicyName, nil)
				metrics.IncrementPermitDecisionsCount()
				writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
				return
			} else {
				decisionRes := createSuccessDecisionResponse(statusMessage, string(oapicodegen.DENY),
					*decisionReq.PolicyName, nil)
				metrics.IncrementDenyDecisionsCount()
				writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
				return
			}

		}

		// If only non-boolean values were collected
		if len(outputMap) > 0 {
			decisionRes := createSuccessDecisionResponse(
				"Decision Not Applicable, Output Only",
				string(oapicodegen.NOTAPPLICABLE),
				*decisionReq.PolicyName, outputMap)
			metrics.IncrementQuerySuccessCount()
			writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
		} else {
			decisionRes := createSuccessDecisionResponse(
				"No Decision: Result is Empty",
				string(oapicodegen.NOTAPPLICABLE),
				*decisionReq.PolicyName, nil)
			metrics.IncrementQueryFailureCount()
			writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
		}
		return

	default:
		// Handle unexpected types in decision.Result
		decisionRes := createSuccessDecisionResponse("Invalid decision result format", string(oapicodegen.DENY), *decisionReq.PolicyName, nil)
		metrics.IncrementDenyDecisionsCount()
		writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
		return
	}

}

// Function to apply policy filter to decision result
func applyPolicyFilter(result map[string]interface{}, filters []string) interface{} {

	// Assuming filter matches specific keys or values
	filteredOutput := make(map[string]interface{})
	for key, value := range result {
		for _, filter := range filters {
			if strings.Contains(key, filter) {
				filteredOutput[key] = value
				break
			}

		}
	}

	return filteredOutput
}
