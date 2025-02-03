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

// Package decision provides functionalities for handling decision requests using OPA (Open Policy Agent).
// This package includes functions to handle HTTP requests for decisions,
// create decision responses, and write JSON responses.
package decision

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/open-policy-agent/opa/sdk"
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
func createSuccessDecisionResponse(policyName string, output map[string]interface{}) *oapicodegen.OPADecisionResponse {
	return &oapicodegen.OPADecisionResponse{
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
	var errorMsg string
	var errorDtls string
	var httpStatus int
	var policyId string

	requestId, _ := processRequestHeaders(req, res)
	log.Debugf("Headers processed for requestId: %s", requestId)

	if !isSystemActive() {
		errorMsg = "System Is In PASSIVE State, unable to handle decision."
		errorDtls = "System Is In PASSIVE State, error handling request."
		httpStatus = http.StatusInternalServerError
		policyId = ""
	} else if req.Method != http.MethodPost {
		errorMsg = "Only POST method allowed."
		errorDtls = req.Method + " MethodNotAllowed"
		httpStatus = http.StatusMethodNotAllowed
		policyId = ""
	} else {
		decisionReq, err := parseRequestBody(req)
		if err != nil {
			errorMsg = "Error decoding request."
			errorDtls = err.Error()
			httpStatus = http.StatusBadRequest
			policyId = ""
		} else if (decisionReq.PolicyName == nil || *decisionReq.PolicyName == "") {
			errorMsg = "Policy details not provided"
			errorDtls = "Policy used to make decision is nil."
			httpStatus = http.StatusBadRequest
			policyId = ""
		} else {
			opa, err := getOpaInstance()
			if err != nil {
				errorMsg = "OPA instance creation error."
				errorDtls = "Failed to get OPA instance."
				httpStatus = http.StatusInternalServerError
				policyId = *decisionReq.PolicyName
			} else {
				processOpaDecision(res, opa, decisionReq)
				return
			}
		}
	}
	//If it comes here then there will be error
	sendErrorResponse(errorMsg, res, errorDtls, httpStatus, policyId)
}

//This function processes the request headers
func processRequestHeaders(req *http.Request, res http.ResponseWriter) (string, *oapicodegen.DecisionParams) {
	requestId := req.Header.Get("X-ONAP-RequestID")
	var parsedUUID *uuid.UUID
	var decisionParams *oapicodegen.DecisionParams

	if requestId != "" && utils.IsValidUUID(requestId) {
		tempUUID, err := uuid.Parse(requestId)
		if err == nil {
			parsedUUID = &tempUUID
			decisionParams = &oapicodegen.DecisionParams{
				XONAPRequestID: (*openapi_types.UUID)(parsedUUID),
			}
			res.Header().Set("X-ONAP-RequestID", decisionParams.XONAPRequestID.String())
		} else {
			log.Warnf("Error Parsing the requestID: %v", err)
		}
	} else {
		requestId = "Unknown"
		res.Header().Set("X-ONAP-RequestID", requestId)
	}

	res.Header().Set("X-LatestVersion", consts.LatestVersion)
	res.Header().Set("X-PatchVersion", consts.PatchVersion)
	res.Header().Set("X-MinorVersion", consts.MinorVersion)

	return requestId, decisionParams
}

// This returns whether the system is active or not
func isSystemActive() bool {
	return pdpstate.GetCurrentState() == model.Active
}

//This method parses the body and checks whether it is properly formatted JSON or not
func parseRequestBody(req *http.Request) (*oapicodegen.OPADecisionRequest, error) {
	var decisionReq oapicodegen.OPADecisionRequest
	if err := json.NewDecoder(req.Body).Decode(&decisionReq); err != nil {
		return nil, err
	}
	return &decisionReq, nil
}

func sendErrorResponse(msg string, res http.ResponseWriter, err string, httpStatus int, policyName string) {
	log.Warnf("%s", msg)
	decisionExc := createDecisionExceptionResponse(http.StatusBadRequest, msg, []string{err}, policyName)
	metrics.IncrementTotalErrorCount()
	writeErrorJSONResponse(res, httpStatus, err, *decisionExc)
}

//This function returns the opasdk instance
func getOpaInstance() (*sdk.OPA, error) {
	return opasdk.GetOPASingletonInstance()
}

//This function processes the OPA decision
func processOpaDecision(res http.ResponseWriter, opa *sdk.OPA, decisionReq *oapicodegen.OPADecisionRequest) {
	ctx := context.Background()
	log.Debugf("SDK making a decision")
	
	options := sdk.DecisionOptions{Path: *decisionReq.PolicyName, Input: decisionReq.Input}
	decisionResult, decisionErr := opa.Decision(ctx, options)
	jsonOutput, err := json.MarshalIndent(decisionResult, "", "  ")
	if err != nil {
		log.Warnf("Error serializing decision output: %v\n", err)
		return
	}
	log.Debugf("RAW opa Decision output:\n%s\n", string(jsonOutput))
	
	if decisionErr != nil {
		handleOpaDecisionError(res, decisionErr, *decisionReq.PolicyName)
		return
	}
	
	var policyFilter []string
	if decisionReq.PolicyFilter != nil {
		policyFilter = *decisionReq.PolicyFilter
	}
	
	if result, ok := decisionResult.Result.(map[string]interface{}); ok {
	    outputMap := processPolicyFilter(result, policyFilter)
	    decisionRes := createSuccessDecisionResponse(*decisionReq.PolicyName, outputMap)
	    if outputMap != nil {
	        metrics.IncrementDecisionSuccessCount()
	    } else {
	        metrics.IncrementDecisionFailureCount()
	    }
	    writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
	} else {
	    decisionRes := createSuccessDecisionResponse(*decisionReq.PolicyName, nil)
	    metrics.IncrementIndeterminantDecisionsCount()
	    writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
	}

}

//This function validates the errors during decision process
func handleOpaDecisionError(res http.ResponseWriter, err error, policyName string) {
	if strings.Contains(err.Error(), "opa_undefined_error") {
		decisionRes := createSuccessDecisionResponse(policyName, nil)
		writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
		metrics.IncrementIndeterminantDecisionsCount()
	} else {
		decisionExc := createDecisionExceptionResponse(http.StatusBadRequest, "Error from OPA while making decision", []string{err.Error()}, policyName)
		metrics.IncrementTotalErrorCount()
		writeErrorJSONResponse(res, http.StatusBadRequest, err.Error(), *decisionExc)
	}
}

//This function processes the policy filters
func processPolicyFilter(result map[string]interface{}, policyFilter []string) map[string]interface{} {
	if len(policyFilter) > 0 {
		filteredResult := applyPolicyFilter(result, policyFilter)
		if filteredMap, ok := filteredResult.(map[string]interface{}); ok && len(filteredMap) > 0 {
			return filteredMap
		}
	}
	return nil
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
