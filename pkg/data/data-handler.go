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
	"errors"
	"fmt"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/open-policy-agent/opa/storage"
	"net/http"
	"path/filepath"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"strings"
)

type (
	checkIfPolicyAlreadyExistsFunc func(policyId string) bool
	validateRequestFunc            func(requestBody *oapicodegen.OPADataUpdateRequest) error
)

var (
	addOp                         storage.PatchOp                = 0
	removeOp                      storage.PatchOp                = 1
	replaceOp                     storage.PatchOp                = 2
	checkIfPolicyAlreadyExistsVar checkIfPolicyAlreadyExistsFunc = policymap.CheckIfPolicyAlreadyExists
	getPolicyByIDVar                                             = getPolicyByID
	extractPatchInfoVar                                          = extractPatchInfo
	bootstrapServers                                             = cfg.BootstrapServer //The Kafka bootstrap server address.
	PatchProducer                 kafkacomm.KafkaProducerInterface
	patchTopic                    = cfg.PatchTopic
	PatchDataVar                  = PatchData
	getOperationTypeVar           = getOperationType
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
	res.Header().Set(consts.ContentType, consts.ApplicationJson)
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

type Policy struct {
	Data          []string `json:"data"`
	Policy        []string `json:"policy"`
	PolicyID      string   `json:"policy-id"`
	PolicyVersion string   `json:"policy-version"`
}

// Function to extract the policy by policyId
func getPolicyByID(policiesMap string, policyId string) (*Policy, error) {
	var policies struct {
		DeployedPolicies []Policy `json:"deployed_policies_dict"`
	}

	if err := json.Unmarshal([]byte(policiesMap), &policies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policies: %v", err)
	}

	for _, policy := range policies.DeployedPolicies {
		if policy.PolicyID == policyId {
			return &policy, nil
		}
	}

	return nil, fmt.Errorf("policy '%s' not found", policyId)
}

func patchHandler(res http.ResponseWriter, req *http.Request) {
	var useKafkaForPatch = cfg.UseKafkaForPatch
	log.Infof("PDP received a request to update data through API")
	constructResponseHeader(res, req)
	var requestBody oapicodegen.OPADataUpdateRequest

	requestBody, err := decodeRequest(req)
	if err != nil {
		sendErrorResponse(res, err.Error(), http.StatusBadRequest)
		return
	}

	dataDir, dirParts := extractDataDir(req)

	if err := validateRequest(&requestBody); err != nil {
		sendErrorResponse(res, err.Error(), http.StatusBadRequest)
		return
	}
	log.Debug("All fields are valid!")
	// Access the data part
	data := requestBody.Data
	log.Infof("data : %s", data)
	policyId := requestBody.PolicyName
	if policyId == ""{
		errMsg := "Policy Id is nil"
		sendErrorResponse(res, errMsg, http.StatusBadRequest)
		return
	}
	log.Infof("policy name : %s", policyId)
	isExists := policymap.CheckIfPolicyAlreadyExists(policyId)
	if !isExists {
		errMsg := "Policy associated with the patch request does not exists"
		sendErrorResponse(res, errMsg, http.StatusBadRequest)
		log.Errorf(errMsg)
		return
	}

	matchFound := validatePolicyDataPathMatched(dirParts, policyId, res)
	if !matchFound {
		return
	}

	patchInfos, err := getPatchInfo(&requestBody.Data, dataDir, res)
	if err != nil {
		log.Warnf("Failed to get Patch Info : %v", err)
		return
	}

	if useKafkaForPatch {
		err := handleDynamicUpdateRequestWithKafka(patchInfos, res)
		if err != nil {
			log.Warnf("Error in handling dynamic update request wit kafka: %v", err)
			return
		}
		res.Header().Set(consts.ContentType, consts.ApplicationJson)
		res.WriteHeader(http.StatusAccepted)
		_, _ = res.Write([]byte(`{"message": "Patch request accepted for processing via kafka and Use the get data url to fetch the latest data. In case of errors, Check logs."uri":"/policy/pdpo/v1/data/""}`))
		metrics.IncrementDynamicDataUpdateSuccessCount()
		return
	}
	if err := PatchData(patchInfos, res); err != nil {
		// Handle the error, for example, log it or return an appropriate response
		log.Errorf("Error encoding JSON response: %s", err)
		return

	}
	metrics.IncrementDynamicDataUpdateSuccessCount()

}

func decodeRequest(req *http.Request) (oapicodegen.OPADataUpdateRequest, error) {
	var requestBody oapicodegen.OPADataUpdateRequest
	if err := json.NewDecoder(req.Body).Decode(&requestBody); err != nil {
		return requestBody, fmt.Errorf("Error in decoding request data: %v", err)
	}
	return requestBody, nil
}

func extractDataDir(req *http.Request) (string, []string) {
	path := strings.TrimPrefix(req.URL.Path, "/policy/pdpo/v1/data")
	dirParts := strings.Split(path, "/")
	return filepath.Join(dirParts...), dirParts
}

func validateRequest(requestBody *oapicodegen.OPADataUpdateRequest) error {
	validationErrors := utils.ValidateOPADataRequest(requestBody)
	if !utils.IsValidData(&requestBody.Data) {
		validationErrors = append(validationErrors, "Data is required and cannot be empty")
	}
	if len(validationErrors) > 0 {
		return fmt.Errorf(strings.Join(validationErrors, ", "))
	}
	return nil
}

func getPatchInfo(data *[]map[string]interface{}, dataDir string, res http.ResponseWriter) ([]opasdk.PatchImpl, error) {
	root := "/" + strings.Trim(dataDir, "/")
	patchInfos, err := extractPatchInfoVar(res, data, root)
	if patchInfos == nil || err != nil {
		return nil, fmt.Errorf("Error in extracting Patch Info : %v", err)
	}
	return patchInfos, nil
}

func handleDynamicUpdateRequestWithKafka(patchInfos []opasdk.PatchImpl, res http.ResponseWriter) error {

	if PatchProducer == nil {
		log.Warnf("Failed to initialize Kafka producer")
		return fmt.Errorf("Failed to initialize Kafka producer")

	}
	sender := &publisher.RealPatchSender{
		Producer: PatchProducer,
	}
	if err := sender.SendPatchMessage(patchInfos); err != nil {
		log.Warnf("Failed to send Patch Messge, %v", err)
		return err
	}

	return nil
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

func extractPatchInfo(res http.ResponseWriter, ops *[]map[string]interface{}, root string) ([]opasdk.PatchImpl, error) {
	var result []opasdk.PatchImpl
	for _, op := range *ops {

		optypeString, opTypeErr := op["op"].(string)
		if !opTypeErr {
			opTypeErrMsg := "Error in getting op type. Op type is not given in request body"
			sendErrorResponse(res, opTypeErrMsg, http.StatusBadRequest)
			log.Errorf(opTypeErrMsg)
			return nil, fmt.Errorf("Error in getting op type. Op type is not given in request body")
		}
		opType, err := getOperationTypeVar(optypeString, res)

		if err != nil {
			log.Warnf("Error in getting opType: %v", err)
			return nil, fmt.Errorf("Error in getting operation type")
		}
		if opType == nil {
			return nil, fmt.Errorf("Error in getting operation Type as opType is Missing")
		}

		impl := opasdk.PatchImpl{
			Op: *opType,
		}

		var value interface{}
		// PATCH request with add or replace opType, MUST contain a "value" member whose content specifies the value to be added / replaced. For remove opType, value does not required
		if optypeString == "add" || optypeString == "replace" {
			value, err = getPatchValue(op, res)
			if err != nil {
				return nil, fmt.Errorf("Error in gatting Value, Value not found")
			}
		}
		impl.Value = value
		storagePath := constructOpStoragePath(op, root, res)
		if storagePath == nil {
			return nil, fmt.Errorf("Failed to construct op Storage Path")
		}
		impl.Path = storagePath

		result = append(result, impl)
	}
	return result, nil
}

func getPatchValue(op map[string]interface{}, res http.ResponseWriter) (interface{}, error) {
	var value interface{}
	var valueErr bool
	value, valueErr = op["value"]
	if !valueErr || isEmpty(value) {
		valueErrMsg := "Error in getting data value. Value is not given in request body"
		sendErrorResponse(res, valueErrMsg, http.StatusBadRequest)
		log.Errorf(valueErrMsg)
		return nil, fmt.Errorf("Error in getting data value. Value is not given in request body")
	}
	return value, nil
}

func isEmpty(data interface{}) bool {
	if data == nil {
		return true // Nil values are considered empty
	}

	switch v := data.(type) {
	case string:
		return len(v) == 0 // Check if string is empty
	case []interface{}:
		return len(v) == 0 // Check if slice is empty
	case map[string]interface{}:
		return len(v) == 0 // Check if map is empty
	case []byte:
		return len(v) == 0 // Check if byte slice is empty
	case int, int8, int16, int32, int64:
		return v == 0 // Zero integers are considered empty
	case uint, uint8, uint16, uint32, uint64:
		return v == 0 // Zero unsigned integers are considered empty
	case float32, float64:
		return v == 0.0 // Zero floats are considered empty
	case bool:
		return !v // `false` is considered empty
	case nil:
		return true // Explicitly checking nil again
	default:
		return false // Other data types are not considered empty
	}
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
		valueErrMsg := "Error in getting data path - Invalid path (/) is used."
		sendErrorResponse(res, valueErrMsg, http.StatusBadRequest)
		log.Errorf(valueErrMsg)
		return nil
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

func validatePolicyDataPathMatched(dirParts []string, policyId string, res http.ResponseWriter) bool {
	matchFound := false
	// Check if all dirParts exist in the matched policy's data key
	log.Debugf("dirParts : %s", dirParts)
	if len(dirParts) > 0 && dirParts[0] == "" {
		dirParts = dirParts[1:]
	}
	finalDirParts := strings.Join(dirParts, ".")
	policiesMap := policymap.LastDeployedPolicies
	matchedPolicy, err := getPolicyByIDVar(policiesMap, policyId)
	if err != nil {
		sendErrorResponse(res, err.Error(), http.StatusBadRequest)
		log.Errorf("Error getting Policy By Id: %v", err.Error())
		return matchFound
	}

	log.Infof("Matched policy: %+v", matchedPolicy)

	// Check if finalDirParts starts with any data key
	for _, dataKey := range matchedPolicy.Data {
		if strings.HasPrefix(finalDirParts, dataKey) {
			matchFound = true
			break
		}
	}
	if !matchFound {
		errMsg := fmt.Sprintf("Dynamic Data add/replace/remove for policy '%s' expected under url path '%v'", policyId, matchedPolicy.Data)
		sendErrorResponse(res, errMsg, http.StatusBadRequest)
		log.Errorf(errMsg)
		return false
	}

	return matchFound
}

func constructOpStoragePath(op map[string]interface{}, root string, res http.ResponseWriter) storage.Path {
	opPath, opPathErr := op["path"].(string)
	if !opPathErr || len(opPath) == 0 {
		opPathErrMsg := "Error in getting data path. Path is not given in request body"
		sendErrorResponse(res, opPathErrMsg, http.StatusBadRequest)
		log.Errorf(opPathErrMsg)
		return nil
	}
	optypeString := op["op"].(string)
	storagePath := constructPath(opPath, optypeString, root, res)
	return storagePath
}

func getOperationType(opType string, res http.ResponseWriter) (*storage.PatchOp, error) {

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
			return nil, errors.New(errMsg)
		}
	}
	return op, nil
}

type NewOpaSDKPatchFunc func(ctx context.Context, patches []opasdk.PatchImpl) error

var NewOpaSDKPatch NewOpaSDKPatchFunc = opasdk.PatchData

func PatchData(patchInfos []opasdk.PatchImpl, res http.ResponseWriter) (err error) {
	if patchInfos != nil {
		patchErr := NewOpaSDKPatch(context.Background(), patchInfos)
		if patchErr != nil {
			errCode := http.StatusInternalServerError

			if strings.Contains((patchErr.Error()), "storage_not_found_error") {
				errCode = http.StatusNotFound
			}
			errMsg := "Error in updating data - " + patchErr.Error()
			if res != nil {
				sendErrorResponse(res, errMsg, errCode)
			}
			log.Errorf(errMsg)
			return patchErr
		}
		log.Infof("Updated the data in the corresponding path successfully\n")
		if res != nil {
			res.WriteHeader(http.StatusNoContent)
		}
	}
	// handled all error scenarios in extractPatchInfo method
	return nil
}

func sendErrorResponse(res http.ResponseWriter, errMsg string, statusCode int) {
	dataExc := createOPADataUpdateExceptionResponse(statusCode, errMsg, "")
	metrics.IncrementDynamicDataUpdateFailureCount()
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
	requestId := req.Header.Get(consts.RequestId)
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
			res.Header().Set(consts.RequestId, decisionParams.XONAPRequestID.String())
		}
	} else {
		requestId = "Unknown"
		res.Header().Set(consts.RequestId, requestId)
	}

	res.Header().Set("X-LatestVersion", consts.LatestVersion)
	res.Header().Set("X-PatchVersion", consts.PatchVersion)
	res.Header().Set("X-MinorVersion", consts.MinorVersion)
}

func getDataInfo(res http.ResponseWriter, req *http.Request) {
	log.Infof("PDP received a request to get data through API")

	constructResponseHeader(res, req)

	urlPath := req.URL.Path

	dataPath := strings.TrimPrefix(urlPath, "/policy/pdpo/v1/data")

	if len(strings.TrimSpace(dataPath)) == 0 {
		// dataPath "/" is used to get entire data
		dataPath = "/"
	}
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

	res.Header().Set(consts.ContentType, consts.ApplicationJson)
	res.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(res).Encode(dataResponse); err != nil {
		// Handle the error, for example, log it or return an appropriate response
		log.Errorf("Error encoding JSON response: %s", err)
	}
}
