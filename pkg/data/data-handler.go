// -
//
//	========================LICENSE_START=================================
//	Copyright (C) 2025: Deutsche Telekom
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	     http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
//	SPDX-License-Identifier: Apache-2.0
//	========================LICENSE_END===================================
package data

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"net/http"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/utils"
	"strings"

	"github.com/open-policy-agent/opa/storage"
	"policy-opa-pdp/pkg/policymap"
)

var (
	addOp     storage.PatchOp = 0
	removeOp  storage.PatchOp = 1
	replaceOp storage.PatchOp = 2
)

// creates a response code map to OPADataUpdateResponse
var httpToOPADataUpdateResponseCode = map[int]oapicodegen.ErrorResponseResponseCode{
	400: oapicodegen.InvalidParameter,
	401: oapicodegen.Unauthorized,
	500: oapicodegen.InternalError,
	404: oapicodegen.ResourceNotFound,
}

// Gets responsecode from map
func getErrorResponseCodeForOPADataUpdate(httpStatus int) oapicodegen.ErrorResponseResponseCode {
	if code, exists := httpToOPADataUpdateResponseCode[httpStatus]; exists {
		return code
	}
	return oapicodegen.InternalError
}

// writes a Error JSON response to the HTTP response writer for OPADataUpdate
func writeOPADataUpdateErrorJSONResponse(res http.ResponseWriter, status int, errorDescription string, dataErrorRes oapicodegen.ErrorResponse) {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(status)
	if err := json.NewEncoder(res).Encode(dataErrorRes); err != nil {
		http.Error(res, err.Error(), status)
	}
}

// creates a OPADataUpdate response based on the provided parameters
func createOPADataUpdateExceptionResponse(statusCode int, errorMessage string, policyName string) *oapicodegen.ErrorResponse {
	responseCode := getErrorResponseCodeForOPADataUpdate(statusCode)
	return &oapicodegen.ErrorResponse{
		ResponseCode: (*oapicodegen.ErrorResponseResponseCode)(&responseCode),
		ErrorMessage: &errorMessage,
		PolicyName:   &policyName,
	}
}

// Validate OPADataUpdateRequest function
func validateOPADataUpdateRequest(request *oapicodegen.OPADataUpdateRequest) []string {
	var validationErrors []string

	// Check if required fields are populated
	dateString := (request.CurrentDate).String()
	if !(utils.IsValidCurrentDate(&dateString)) {
		validationErrors = append(validationErrors, "CurrentDate is required")
	}

	// Validate CurrentDateTime format
	if !(utils.IsValidTime(request.CurrentDateTime)) {
		validationErrors = append(validationErrors, "CurrentDateTime is invalid or missing")
	}

	// Validate CurrentTime format
	if !(utils.IsValidCurrentTime(request.CurrentTime)) {
		validationErrors = append(validationErrors, "CurrentTime is invalid or missing")
	}

	// Validate Data field (ensure it's not nil and has items)
	if !(utils.IsValidData(request.Data)) {
		validationErrors = append(validationErrors, "Data is required and cannot be empty")
	}

	// Validate TimeOffset format (e.g., +02:00 or -05:00)
	if !(utils.IsValidTimeOffset(request.TimeOffset)) {
		validationErrors = append(validationErrors, "TimeOffset is invalid or missing")
	}

	// Validate TimeZone format (e.g., 'America/New_York')
	if !(utils.IsValidTimeZone(request.TimeZone)) {
		validationErrors = append(validationErrors, "TimeZone is invalid or missing")
	}

	// Optionally, check if 'OnapComponent', 'OnapInstance', 'OnapName', and 'PolicyName' are provided
	if !(utils.IsValidString(request.OnapComponent)) {
		validationErrors = append(validationErrors, "OnapComponent is required")
	}

	if !(utils.IsValidString(request.OnapInstance)) {
		validationErrors = append(validationErrors, "OnapInstance is required")
	}

	if !(utils.IsValidString(request.OnapName)) {
		validationErrors = append(validationErrors, "OnapName is required")
	}

	if !(utils.IsValidString(request.PolicyName)) {
		validationErrors = append(validationErrors, "PolicyName is required and cannot be empty")
	}

	// Return all validation errors (if any)
	return validationErrors
}

func patchHandler(res http.ResponseWriter, req *http.Request) {
	log.Infof("PDP received a request to update data through API")
	constructResponseHeader(res, req)
	var requestBody oapicodegen.OPADataUpdateRequest
	if err := json.NewDecoder(req.Body).Decode(&requestBody); err != nil {
		errMsg := "Error in decoding the request data - " + err.Error()
		sendErrorResponse(res, errMsg, http.StatusBadRequest)
		log.Errorf(errMsg)
		return
	}
	path := strings.TrimPrefix(req.URL.Path, "/policy/pdpo/v1/data/")
	dirParts := strings.Split(path, "/")
	dataDir := filepath.Join(dirParts...)
	log.Infof("dataDir : %s", dataDir)

	// Validate the request
	validationErrors := validateOPADataUpdateRequest(&requestBody)

	// Print validation errors
	if len(validationErrors) > 0 {
		errMsg := strings.Join(validationErrors, ", ")
		log.Errorf("Facing validation error in requestbody - %s", errMsg)
		sendErrorResponse(res, errMsg, http.StatusBadRequest)
		return
	} else {
		log.Errorf("All fields are valid!")
		// Access the data part
		data := requestBody.Data
		log.Infof("data : %s", data)
		policyId := requestBody.PolicyName
		log.Infof("policy name : %s", *policyId)
		isExists := policymap.CheckIfPolicyAlreadyExists(*policyId)
		if !isExists {
			errMsg := "Policy associated with the patch request does not exists"
			sendErrorResponse(res, errMsg, http.StatusBadRequest)
			log.Errorf(errMsg)
			return
		}
		if err := patchData(dataDir, data, res); err != nil {
                        // Handle the error, for example, log it or return an appropriate response
                        log.Errorf("Error encoding JSON response: %s", err)
                }
	}
}

func DataHandler(res http.ResponseWriter, req *http.Request) {
	reqMethod := req.Method
	switch reqMethod {
	case "PATCH":
		patchHandler(res, req)
	case "GET":
		getDataInfo(res, req)
	default:
		invalidMethodHandler(res, reqMethod)
	}
}

func extractPatchInfo(res http.ResponseWriter, ops *[]map[string]interface{}, root string) (result []opasdk.PatchImpl) {
	for _, op := range *ops {
		// Extract the operation, path, and value from the map
		optypeString, opTypeErr := op["op"].(string)
		if !opTypeErr {
			opTypeErrMsg := "Error in getting op type. Op type is not given in request body"
			sendErrorResponse(res, opTypeErrMsg, http.StatusInternalServerError)
			log.Errorf(opTypeErrMsg)
			return nil
		}
		opType := getOperationType(optypeString, res)

		if opType == nil {
			return nil
		}
		impl := opasdk.PatchImpl{
			Op: *opType,
		}

		var value interface{}
		var valueErr bool
		// PATCH request with add or replace opType, MUST contain a "value" member whose content specifies the value to be added / replaced. For remove opType, value does not required
		if optypeString == "add" || optypeString == "replace" {
			value, valueErr = op["value"]
			if !valueErr {
				valueErrMsg := "Error in getting data value. Value is not given in request body"
				sendErrorResponse(res, valueErrMsg, http.StatusInternalServerError)
				log.Errorf(valueErrMsg)
				return nil
			}
		}
		impl.Value = value

		opPath, opPathErr := op["path"].(string)
		if !opPathErr {
			opPathErrMsg := "Error in getting data path. Path is not given in request body"
			sendErrorResponse(res, opPathErrMsg, http.StatusInternalServerError)
			log.Errorf(opPathErrMsg)
			return nil
		}
		storagePath := constructPath(opPath, optypeString, root, res)
		if storagePath == nil {
			return nil
		}
		impl.Path = storagePath

		result = append(result, impl)
	}
	//log.Debugf("result : %s", result)
	return result
}

func constructPath(opPath string, opType string, root string, res http.ResponseWriter) (storagePath storage.Path) {
	// Construct patch path.
	log.Debugf("root: %s", root)

	path := strings.Trim(opPath, "/")
	log.Debugf("path : %s", path)
	/*
		Eg: 1
		path in curl = v1/data/test
		path in request body = /test1
		consolidated path = /test/test1
		so, value should be updated under /test/test1

		Eg: 2
		path in curl = v1/data/
		path in request body = /test1
		consolidated path = /test1
		so, value should be updated under /test1
	*/
	if len(path) > 0 {
		if root == "/" {
			path = root + path
		} else {
			path = root + "/" + path
		}
	} else {
		if opType == "remove" {
			valueErrMsg := "Error in getting data path - Invalid path (/) is used."
			sendErrorResponse(res, valueErrMsg, http.StatusInternalServerError)
			log.Errorf(valueErrMsg)
			return nil
		}
		path = root
	}

	log.Infof("calling ParsePatchPathEscaped to check the path")
	storagePath, ok := opasdk.ParsePatchPathEscaped(path)

	if !ok {
		valueErrMsg := "Error in checking patch path - Bad patch path used :" + path
		sendErrorResponse(res, valueErrMsg, http.StatusInternalServerError)
		log.Errorf(valueErrMsg)
		return nil
	}

	return storagePath
}

func getOperationType(opType string, res http.ResponseWriter) *storage.PatchOp {
	var op *storage.PatchOp
	switch opType {
	case "add":
		op = &addOp
	case "remove":
		op = &removeOp
	case "replace":
		op = &replaceOp
	default:
		{
			errMsg := "Error in getting op type : Invalid operation type (" + opType + ") is used. Only add, remove and replace operation types are supported"
			sendErrorResponse(res, errMsg, http.StatusBadRequest)
			log.Errorf(errMsg)
			return nil
		}
	}
	return op
}

type NewOpaSDKPatchFunc func(ctx context.Context, patches []opasdk.PatchImpl) error

var NewOpaSDKPatch NewOpaSDKPatchFunc = opasdk.PatchData

func patchData(root string, ops *[]map[string]interface{}, res http.ResponseWriter) (err error) {
	root = "/" + strings.Trim(root, "/")
	patchInfos := extractPatchInfo(res, ops, root)

	if patchInfos != nil {
		patchErr := NewOpaSDKPatch(context.Background(), patchInfos)
		if patchErr != nil {
			errCode := http.StatusInternalServerError

			if strings.Contains((patchErr.Error()), "storage_not_found_error") {
				errCode = http.StatusNotFound
			}
			errMsg := "Error in updating data - " + patchErr.Error()
			sendErrorResponse(res, errMsg, errCode)
			log.Errorf(errMsg)
			return
		}
		log.Infof("Updated the data in the corresponding path successfully\n")
		res.WriteHeader(http.StatusNoContent)
	}
	// handled all error scenarios in extractPatchInfo method
	return nil
}

func sendErrorResponse(res http.ResponseWriter, errMsg string, statusCode int) {
	dataExc := createOPADataUpdateExceptionResponse(statusCode, errMsg, "")
	metrics.IncrementTotalErrorCount()
	writeOPADataUpdateErrorJSONResponse(res, statusCode, errMsg, *dataExc)
}

func invalidMethodHandler(res http.ResponseWriter, method string) {
	log.Errorf("Invalid method type")
	resMsg := "Only PATCH and GET Method Allowed"
	msg := "MethodNotAllowed"
	sendErrorResponse(res, (method + msg + " - " + resMsg), http.StatusBadRequest)
	log.Errorf(method + msg + " - " + resMsg)
	return
}

func constructResponseHeader(res http.ResponseWriter, req *http.Request) {
	requestId := req.Header.Get("X-ONAP-RequestID")
	var parsedUUID *uuid.UUID
	var decisionParams *oapicodegen.DecisionParams

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
}

func getDataInfo(res http.ResponseWriter, req *http.Request) {
	log.Infof("PDP received a request to get data through API")

	constructResponseHeader(res, req)

	urlPath := req.URL.Path
	dataPath := strings.ReplaceAll(urlPath, "/policy/pdpo/v1/data", "")
	log.Debugf("datapath to get Data : %s\n", dataPath)

	getData(res, dataPath)
}

type NewOpaSDKGetFunc func(ctx context.Context, dataPath string) (data *oapicodegen.OPADataResponse_Data, err error)

var NewOpaSDK NewOpaSDKGetFunc = opasdk.GetDataInfo

func getData(res http.ResponseWriter, dataPath string) {

	var dataResponse oapicodegen.OPADataResponse
	data, getErr := NewOpaSDK(context.Background(), dataPath)
	if getErr != nil {
		errCode := http.StatusInternalServerError

		if strings.Contains((getErr.Error()), "storage_not_found_error") {
			errCode = http.StatusNotFound
		}

		sendErrorResponse(res, "Error in getting data - "+getErr.Error(), errCode)
		log.Errorf("Error in getting data - %s ", getErr.Error())
		return
	}

	if data != nil {
		dataResponse.Data = data
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(res).Encode(dataResponse); err != nil {
                // Handle the error, for example, log it or return an appropriate response
                log.Errorf("Error encoding JSON response: %s", err)
	}
}
