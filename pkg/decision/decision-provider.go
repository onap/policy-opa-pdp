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
	"fmt"
	"net/http"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/pdpstate"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"sort"
	"strings"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/open-policy-agent/opa/sdk"
)

// creates a response code map to ErrorResponseResponseCode
var httpToResponseCode = map[int]oapicodegen.ErrorResponseResponseCode{
	400: oapicodegen.BadRequest,
	401: oapicodegen.Unauthorized,
	500: oapicodegen.InternalError,
}

// Gets responsecode from map
func getErrorResponseResponseCode(httpStatus int) oapicodegen.ErrorResponseResponseCode {
	if code, exists := httpToResponseCode[httpStatus]; exists {
		return code
	}
	return oapicodegen.InternalError
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

// creates a success decision response
func createSuccessDecisionResponse(policyName string, policyVersion string, output map[string]interface{}) *oapicodegen.OPADecisionResponse {
	return &oapicodegen.OPADecisionResponse{
		PolicyName:    &policyName,
		PolicyVersion: &policyVersion,
		Output:        &output,
	}
}

// creates a decision response based on the provided parameters
func createSuccessDecisionResponseWithStatus(policyName string, policyVersion string, output map[string]interface{}, statusMessage string) *oapicodegen.OPADecisionResponse {
	return &oapicodegen.OPADecisionResponse{
		PolicyName:    &policyName,
		PolicyVersion: &policyVersion,
		Output:        &output,
		StatusMessage: &statusMessage,
	}
}

// creates a decision response based on the provided parameters
func createDecisionExceptionResponse(statusCode int, errorMessage string, policyName string, PolicyVersion string) *oapicodegen.ErrorResponse {

	responseCode := getErrorResponseResponseCode(statusCode)
	return &oapicodegen.ErrorResponse{
		ResponseCode:  (*oapicodegen.ErrorResponseResponseCode)(&responseCode),
		ErrorMessage:  &errorMessage,
		PolicyName:    &policyName,
		PolicyVersion: &PolicyVersion,
	}
}

// handles HTTP requests for decisions using OPA.
func OpaDecision(res http.ResponseWriter, req *http.Request) {
	log.Debugf("PDP received a decision request.")
	var errorDtls string
	var httpStatus int
	var policyId = ""
	var policyVersion = ""

	requestId, _ := processRequestHeaders(req, res)
	log.Debugf("Headers processed for requestId: %s", requestId)

	if !isSystemActive() {
		errorDtls = "System Is In PASSIVE State, error handling request."
		httpStatus = http.StatusInternalServerError
	} else if req.Method != http.MethodPost {
		errorDtls = req.Method + " MethodNotAllowed"
		httpStatus = http.StatusMethodNotAllowed
	} else {
		handleDecisionRequest(res, req, &errorDtls, &httpStatus, &policyId, &policyVersion)
	}
	if errorDtls != "" {
		sendDecisionErrorResponse(errorDtls, res, httpStatus, policyId, policyVersion)
	}
}

// Function to handle decision request logic
func handleDecisionRequest(res http.ResponseWriter, req *http.Request, errorDtls *string, httpStatus *int, policyId *string, policyVersion *string) {
	decisionReq, err := parseRequestBody(req)
	if err != nil {
		*errorDtls = err.Error()
		*httpStatus = http.StatusBadRequest
		return
	}

	*policyId = decisionReq.PolicyName
	// Validate the request body
	validationErrors := utils.ValidateOPADataRequest(decisionReq)

	if decisionReq.PolicyFilter == nil || len(decisionReq.PolicyFilter) == 0 {
		validationErrors = append(validationErrors, "PolicyFilter is required")
	}
	if len(validationErrors) > 0 {
		*errorDtls = strings.Join(validationErrors, ", ")
		log.Errorf("Facing validation error in requestbody - %s", *errorDtls)
		*httpStatus = http.StatusBadRequest
		return
	}
	log.Debugf("Validation successful for request fields")
	// If validation passes, handle the decision request
	decisionReq.PolicyName = strings.ReplaceAll(decisionReq.PolicyName, ".", "/")
	handlePolicyValidation(res, decisionReq, errorDtls, httpStatus, policyId, policyVersion)
}

// Function to handle policy validation logic
func handlePolicyValidation(res http.ResponseWriter, decisionReq *oapicodegen.OPADecisionRequest, errorDtls *string, httpStatus *int, policyId *string, policyVersion *string) {
	policiesMap := policymap.LastDeployedPolicies
	if policiesMap == "" {
		*errorDtls = "No policies are deployed."
		*httpStatus = http.StatusBadRequest
		return
	}

	extractedPolicies := policymap.ExtractDeployedPolicies(policiesMap)
	if extractedPolicies == nil {
		log.Warnf("No Policies extracted from Policy Map")
		*errorDtls = "No policies are deployed."
		*httpStatus = http.StatusBadRequest
		return
	}

	if !policyExists(decisionReq.PolicyName, extractedPolicies) {
		*errorDtls = fmt.Sprintf("Policy Name %s does not exist", decisionReq.PolicyName)
		*httpStatus = http.StatusBadRequest
		return
	}

	// Process OPA decision
	*policyVersion = getPolicyVersion(decisionReq.PolicyName, extractedPolicies)
	opa, err := getOpaInstance()
	if err != nil {
		*errorDtls = "Failed to get OPA instance."
		*httpStatus = http.StatusInternalServerError
		*policyId = decisionReq.PolicyName
		return
	}

	processOpaDecision(res, opa, decisionReq, *policyVersion)
}

// Function to check if policy exists in extracted policies
func policyExists(policyName string, extractedPolicies []model.ToscaConceptIdentifier) bool {
	for _, policy := range extractedPolicies {
		if strings.ReplaceAll(policy.Name, ".", "/") == policyName {
			return true
		}
	}
	return false
}

// This function processes the request headers
func processRequestHeaders(req *http.Request, res http.ResponseWriter) (string, *oapicodegen.DecisionParams) {
	requestId := req.Header.Get(consts.RequestId)
	var parsedUUID *uuid.UUID
	var decisionParams *oapicodegen.DecisionParams

	if requestId != "" && utils.IsValidUUID(requestId) {
		tempUUID, err := uuid.Parse(requestId)
		if err == nil {
			parsedUUID = &tempUUID
			decisionParams = &oapicodegen.DecisionParams{
				XONAPRequestID: (*openapi_types.UUID)(parsedUUID),
			}
			res.Header().Set(consts.RequestId, decisionParams.XONAPRequestID.String())
		} else {
			log.Warnf("Error Parsing the requestID: %v", err)
		}
	} else {
		requestId = "Unknown"
		res.Header().Set(consts.RequestId, requestId)
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

// This method parses the body and checks whether it is properly formatted JSON or not
func parseRequestBody(req *http.Request) (*oapicodegen.OPADecisionRequest, error) {
	var decisionReq oapicodegen.OPADecisionRequest
	if err := json.NewDecoder(req.Body).Decode(&decisionReq); err != nil {
		return nil, err
	}
	return &decisionReq, nil
}

// This function sends the error response
func sendDecisionErrorResponse(msg string, res http.ResponseWriter, httpStatus int, policyName string, policyVersion string) {
	log.Warnf("%s", msg)
	decisionExc := createDecisionExceptionResponse(httpStatus, msg, policyName, policyVersion)
	metrics.IncrementDecisionFailureCount()
	metrics.IncrementTotalErrorCount()
	writeErrorJSONResponse(res, httpStatus, msg, *decisionExc)
}

type OPASingletonInstanceFunc func() (*sdk.OPA, error)

var OPASingletonInstance OPASingletonInstanceFunc = opasdk.GetOPASingletonInstance

// This function returns the opasdk instance
func getOpaInstance() (*sdk.OPA, error) {
	return OPASingletonInstance()
}

type OPADecisionFunc func(opa *sdk.OPA, ctx context.Context, options sdk.DecisionOptions) (*sdk.DecisionResult, error)

var OPADecision OPADecisionFunc = (*sdk.OPA).Decision

// This function processes the OPA decision
func processOpaDecision(res http.ResponseWriter, opa *sdk.OPA, decisionReq *oapicodegen.OPADecisionRequest, policyVersion string) {
	ctx := context.Background()
	log.Debugf("SDK making a decision")
	var decisionRes *oapicodegen.OPADecisionResponse
	//OPA is seding success with a warning message if "input" parameter is missing, so we need to send success response
	inputBytes, err := json.Marshal(decisionReq.Input)
	if err != nil {
		log.Warnf("Failed to unmarshal decision Request Input: %vg", err)
		return
	}
	if inputBytes == nil || len(inputBytes) == 0 || string(inputBytes) == "null" {
		statusMessage := "{\"warning\":{\"code\":\"api_usage_warning\",\"message\":\"'input' key missing from the request\"}}"
		decisionRes = createSuccessDecisionResponseWithStatus(decisionReq.PolicyName, policyVersion, nil, statusMessage)
	} else {
		options := sdk.DecisionOptions{Path: decisionReq.PolicyName, Input: decisionReq.Input}
		decisionResult, decisionErr := OPADecision(opa, ctx, options)
		jsonOutput, err := json.MarshalIndent(decisionResult, "", "  ")
		if err != nil {
			log.Warnf("Error serializing decision output: %v\n", err)
			return
		}
		log.Debugf("RAW opa Decision output:\n%s\n", string(jsonOutput))

		//while making decision . is replaced by /. reverting back.
		decisionReq.PolicyName = strings.ReplaceAll(decisionReq.PolicyName, "/", ".")

		if decisionErr != nil {
			sendDecisionErrorResponse(decisionErr.Error(), res, http.StatusInternalServerError, decisionReq.PolicyName, policyVersion)
			return
		}
		var policyFilter []string
		if decisionReq.PolicyFilter != nil {
			policyFilter = decisionReq.PolicyFilter
		}
		result, _ := decisionResult.Result.(map[string]interface{})
		outputMap, unmatchedFilters, validPolicyFilters := processPolicyFilter(result, policyFilter)

		if len(unmatchedFilters) > 0 {
			message := fmt.Sprintf("Policy Filter(s) not matching, Valid Filter(s) are: [%s]", strings.Join(validPolicyFilters, ", "))
			decisionRes = createSuccessDecisionResponseWithStatus(decisionReq.PolicyName, policyVersion, outputMap, message)
		} else {
			decisionRes = createSuccessDecisionResponse(decisionReq.PolicyName, policyVersion, outputMap)
		}
	}
	metrics.IncrementDecisionSuccessCount()
	writeOpaJSONResponse(res, http.StatusOK, *decisionRes)
}

// This function processes the policy filters
func processPolicyFilter(result map[string]interface{}, policyFilter []string) (map[string]interface{}, []string, []string) {
	if len(policyFilter) > 0 {
		filteredResult, unmatchedFilters, validfilters := applyPolicyFilter(result, policyFilter)
		if len(filteredResult) > 0 {
			return filteredResult, unmatchedFilters, validfilters
		}
	}
	return nil, policyFilter, getValidPolicyFilters(result)
}

// Get Valid Filters and collects unmatched filters
func applyPolicyFilter(result map[string]interface{}, filters []string) (map[string]interface{}, []string, []string) {
	filteredOutput := make(map[string]interface{})
	unmatchedFilters := []string{}

	validFilters := getValidPolicyFilters(result)
	for _, filter := range filters {
		if filter == "" {
			// when filter is "" empty, the entire resultant data will be reported
			return result, nil, validFilters
		}
		// Try to find the value in the result map
		if value := findNestedValue(result, strings.Split(filter, "/")); value != nil {
			filteredOutput[filter] = value // Store using full path
		} else if value, exists := result[filter]; exists {
			// Allow direct key match (for non-nested filters)
			filteredOutput[filter] = value
		} else {
			unmatchedFilters = append(unmatchedFilters, filter) // Collect unmatched filters
		}
	}

	return filteredOutput, unmatchedFilters, validFilters
}

// handles the nested Policy Filters available when multiple rego files are included.
func findNestedValue(opaSdkResult map[string]interface{}, keys []string) interface{} {
	if len(keys) == 0 {
		return nil
	}
	currentMap := opaSdkResult

	for _, key := range keys {
		value, exists := currentMap[key]
		if !exists {
			return nil // Key doesn't exist
		}

		// If it's a nested map, continue traversal
		if nextNestedMap, ok := value.(map[string]interface{}); ok {
			currentMap = nextNestedMap
		} else {
			return value // Return final value (non-map)
		}
	}
	return currentMap
}

// returns the valid Policy Filters available
func getValidPolicyFilters(opaSdkResult map[string]interface{}) []string {
	keys := make([]string, 0)

	for k, v := range opaSdkResult {
		keys = append(keys, k)
		if nestedMap, ok := v.(map[string]interface{}); ok {
			for nestedKey := range nestedMap {
				keys = append(keys, k+"/"+nestedKey)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

func getPolicyVersion(policyName string, extractedPolicies []model.ToscaConceptIdentifier) string {
	for _, policy := range extractedPolicies {
		if strings.ReplaceAll(policy.Name, ".", "/") == policyName {
			return policy.Version
		}
	}
	return "unknown"

}
