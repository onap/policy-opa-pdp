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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/opasdk"
	"strings"
	"testing"
	"time"
)

func TestGetErrorResponseCodeForOPADataUpdate(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected oapicodegen.ErrorResponseResponseCode
	}{
		{"Invalid Parameter", 400, oapicodegen.InvalidParameter},
		{"Unauthorized", 401, oapicodegen.Unauthorized},
		{"Internal Error", 500, oapicodegen.InternalError},
		{"Resource Not Found", 404, oapicodegen.ResourceNotFound},
		{"Unknown Error", 999, oapicodegen.InternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getErrorResponseCodeForOPADataUpdate(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPatchHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("PATCH", "/policy/pdpo/v1/data/", bytes.NewBuffer([]byte("{invalid_json}")))
	res := httptest.NewRecorder()

	patchHandler(res, req)

	assert.Equal(t, http.StatusBadRequest, res.Code)
	assert.Contains(t, res.Body.String(), "Error in decoding")
}

func TestPatchHandlerWithInvalidData(t *testing.T) {
	ctime := "08:26:41"
	timeZone := "America/New_York"
	timeOffset := "+02:00"
	onapComp := "COMPONENT"
	onapIns := "INSTANCE"
	onapName := "ONAP"
	policyName := "TestPolicy"
	parsedDate, err := time.Parse("2006-01-02", "2024-02-12")
	if err != nil {
		fmt.Println("error in parsedDate")
	}
	currentDate := openapi_types.Date{Time: parsedDate}
	currentDateTime, err := time.Parse(time.RFC3339, "2024-02-12T12:00:00Z")
	if err != nil {
		fmt.Println("error in currentDateTime")
	}
	var data []map[string]interface{}

	data = append(data, map[string]interface{}{"key": "value"})

	validRequest := &oapicodegen.OPADataUpdateRequest{
		CurrentDate:     &currentDate,
		CurrentDateTime: &currentDateTime,
		CurrentTime:     &ctime,
		TimeOffset:      &timeOffset,
		TimeZone:        &timeZone,
		OnapComponent:   &onapComp,
		OnapInstance:    &onapIns,
		OnapName:        &onapName,
		PolicyName:      &policyName,
		Data:            &data,
	}

	// Marshal the request to JSON
	requestBody, err := json.Marshal(validRequest)
	if err != nil {
		panic(err)
	}

	req := httptest.NewRequest("PATCH", "/policy/pdpo/v1/data/valid/path", bytes.NewReader(requestBody))
	res := httptest.NewRecorder()
	patchHandler(res, req)
	assert.Equal(t, http.StatusBadRequest, res.Code)
}

func TestPatchHandlerWithInvalidPolicyId(t *testing.T) {
	ctime := "08:26:41.857Z"
	timeZone := "America/New_York"
	timeOffset := "+02:00"
	onapComp := "COMPONENT"
	onapIns := "INSTANCE"
	onapName := "ONAP"
	policyName := "TestPolicy"
	parsedDate, err := time.Parse("2006-01-02", "2024-02-12")
	if err != nil {
		fmt.Println("error in parsedDate")
	}
	currentDate := openapi_types.Date{Time: parsedDate}
	currentDateTime, err := time.Parse(time.RFC3339, "2024-02-12T12:00:00Z")
	if err != nil {
		fmt.Println("error in currentDateTime")
	}
	var data []map[string]interface{}

	data = append(data, map[string]interface{}{"key": "value"})

	validRequest := &oapicodegen.OPADataUpdateRequest{
		CurrentDate:     &currentDate,
		CurrentDateTime: &currentDateTime,
		CurrentTime:     &ctime,
		TimeOffset:      &timeOffset,
		TimeZone:        &timeZone,
		OnapComponent:   &onapComp,
		OnapInstance:    &onapIns,
		OnapName:        &onapName,
		PolicyName:      &policyName,
		Data:            &data,
	}
	// Marshal the request to JSON
	requestBody, err := json.Marshal(validRequest)
	if err != nil {
		panic(err)
	}

	req := httptest.NewRequest("PATCH", "/policy/pdpo/v1/data/valid/path", bytes.NewReader(requestBody))
	res := httptest.NewRecorder()

	patchHandler(res, req)

	assert.Equal(t, http.StatusBadRequest, res.Code)
}

func TestPatchData_failure(t *testing.T) {
	var data []map[string]interface{}

	data = nil
	root := "/test"
	res := httptest.NewRecorder()
	result := patchData(root, &data, res)
	assert.Nil(t, result)
}

func TestPatchData_storageFail(t *testing.T) {
	// Backup original function
	originalOpaSDKPatchData := NewOpaSDKPatch
	NewOpaSDKPatch = func(ctx context.Context, patches []opasdk.PatchImpl) error {
		return errors.New("storage_not_found_error")
	}
	defer func() { NewOpaSDKPatch = originalOpaSDKPatchData }() // Restore after test
	var data []map[string]interface{}
	data = append(data, map[string]interface{}{"op": "add", "path": "/test", "value": "try"})

	root := "/test"
	res := httptest.NewRecorder()
	result := patchData(root, &data, res)
	assert.Equal(t, http.StatusNotFound, res.Code)
	assert.Nil(t, result)
}

func Test_extractPatchInfo_OPTypefail(t *testing.T) {
	var data []map[string]interface{}
	data = append(data, map[string]interface{}{"path": "/test", "value": "try"})

	root := "/test"
	res := httptest.NewRecorder()
	extractPatchInfo(res, &data, root)
	assert.Equal(t, http.StatusInternalServerError, res.Code)
}

func Test_extractPatchInfo_Pathfail(t *testing.T) {
	var data []map[string]interface{}
	data = append(data, map[string]interface{}{"op": "add", "value": "try"})

	root := "/test"
	res := httptest.NewRecorder()
	extractPatchInfo(res, &data, root)
	assert.Equal(t, http.StatusInternalServerError, res.Code)
}

func Test_extractPatchInfo_valuefail(t *testing.T) {
	var data []map[string]interface{}
	data = append(data, map[string]interface{}{"path": "/test", "op": "add"})

	root := "/test"
	res := httptest.NewRecorder()
	extractPatchInfo(res, &data, root)
	assert.Equal(t, http.StatusInternalServerError, res.Code)
}

func TestPatchData_success(t *testing.T) {
	// Backup original function
	originalOpaSDKPatchData := NewOpaSDKPatch
	NewOpaSDKPatch = func(ctx context.Context, patches []opasdk.PatchImpl) error {
		return nil
	}
	defer func() { NewOpaSDKPatch = originalOpaSDKPatchData }() // Restore after test
	var data []map[string]interface{}
	data = append(data, map[string]interface{}{"op": "add", "path": "/test", "value": "try"})

	root := "/test"
	res := httptest.NewRecorder()
	patchData(root, &data, res)
	assert.Equal(t, http.StatusNoContent, res.Code)
}

func TestConstructPath(t *testing.T) {
	tests := []struct {
		name       string
		opPath     string
		opType     string
		root       string
		expectsNil bool
	}{
		{"Valid Path", "/test1", "add", "/v1/data", false},
		{"Invalid Remove Path", "/", "remove", "/v1/data", true},
		{"Invalid empty Path", "", "add", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := httptest.NewRecorder()
			result := constructPath(tt.opPath, tt.opType, tt.root, res)
			if tt.expectsNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestGetOperationType(t *testing.T) {
	tests := []struct {
		name       string
		opType     string
		expectsNil bool
	}{
		{"Valid opType", "add", false},
		{"Valid opType", "remove", false},
		{"Valid opType", "replace", false},
		{"Invalid opType", "try", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := httptest.NewRecorder()
			result := getOperationType(tt.opType, res)
			if tt.expectsNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

// Test to check UUID is valid
func Test_valid_UUID(t *testing.T) {
	req := httptest.NewRequest("PATCH", "/policy/pdpo/v1/data/missing/path", nil)
	req.Header.Set("X-ONAP-RequestID", "123e4567-e89b-12d3-a456-426614174000")
	res := httptest.NewRecorder()
	DataHandler(res, req)
	assert.Equal(t, "123e4567-e89b-12d3-a456-426614174000", res.Header().Get("X-ONAP-RequestID"), "X-ONAP-RequestID header mismatch")
}

// Test to check UUID is in-valid
func Test_inValid_UUID(t *testing.T) {
	req := httptest.NewRequest("PATCH", "/policy/pdpo/v1/data/missing/path", nil)
	req.Header.Set("X-ONAP-RequestID", "invalid-uuid")
	res := httptest.NewRecorder()
	DataHandler(res, req)
	assert.Equal(t, http.StatusBadRequest, res.Code)
}

func TestDataHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "Invalid method",
			method:         "POST", // assuming the handler doesn't handle POST
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a request with the given method
			req := httptest.NewRequest(tt.method, "/policy/pdpo/v1/data/mismatch/path", nil)

			// Create a ResponseRecorder to record the response
			res := httptest.NewRecorder()

			// Call the DataHandler with the mock request and recorder
			DataHandler(res, req)

			// Check if the response status code matches the expected status
			if res.Code != tt.expectedStatus {
				t.Errorf("expected status %v, got %v", tt.expectedStatus, res.Code)
			}
		})
	}
}

func TestSendErrorResponse(t *testing.T) {
	res := httptest.NewRecorder()
	sendErrorResponse(res, "Test Error", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, res.Code)
	assert.Contains(t, res.Body.String(), "Test Error")
}

func TestInvalidMethodHandler(t *testing.T) {
	res := httptest.NewRecorder()
	invalidMethodHandler(res, "POST")

	assert.Equal(t, http.StatusBadRequest, res.Code)
	assert.Contains(t, res.Body.String(), "Only PATCH and GET Method Allowed")
}

func TestGetDataInfo(t *testing.T) {
	// Backup original function
	originalOpaSDKGetDataInfo := NewOpaSDK
	NewOpaSDK = func(ctx context.Context, dataPath string) (data *oapicodegen.OPADataResponse_Data, err error) {
		return nil, errors.New("storage_not_found_error")
	}
	defer func() { NewOpaSDK = originalOpaSDKGetDataInfo }() // Restore after test

	// Create a mock request
	req := httptest.NewRequest("GET", "/policy/pdpo/v1/data/missing/path", nil)
	res := httptest.NewRecorder()

	// Call the function under test
	getDataInfo(res, req)

	// Check response status code
	if res.Code == http.StatusNotFound {
		// Validate response body
		errorMessage := strings.TrimSpace(res.Body.String())
		assert.Contains(t, errorMessage, "storage_not_found_error")
	}
}

// Mock opasdk.GetDataInfo
var mockGetData func(ctx context.Context, dataPath string) (*oapicodegen.OPADataResponse_Data, error)

func TestGetData(t *testing.T) {

	// Backup original function
	originalOpaSDKGetDataInfo := NewOpaSDK
	NewOpaSDK = func(ctx context.Context, dataPath string) (data *oapicodegen.OPADataResponse_Data, err error) {
		return mockGetData(ctx, dataPath)
	}
	defer func() { NewOpaSDK = originalOpaSDKGetDataInfo }() // Restore after test

	tests := []struct {
		name           string
		requestURL     string
		mockResponse   interface{}
		mockError      error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Success - Data Retrieved",
			requestURL:     "/policy/pdpo/v1/data/example/path",
			mockResponse:   map[string]string{"key": "value"},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody:   `{"data":{"key":"value"}}`,
		},
		{
			name:           "Error - Storage Not Found",
			requestURL:     "/policy/pdpo/v1/data/missing/path",
			mockResponse:   nil,
			mockError:      errors.New("storage_not_found_error"),
			expectedStatus: http.StatusNotFound,
			expectedBody:   "Error in getting data - storage_not_found_error",
		},
		{
			name:           "Error - Internal Server Error",
			requestURL:     "/policy/pdpo/v1/data/error/path",
			mockResponse:   nil,
			mockError:      errors.New("internal server failure"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Error in getting data - internal server failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock `opasdk.GetDataInfo` behavior
			mockGetData = func(ctx context.Context, dataPath string) (*oapicodegen.OPADataResponse_Data, error) {
				var resData oapicodegen.OPADataResponse_Data
				jsonData, err := json.Marshal(tt.mockResponse)
				if err != nil {
					fmt.Printf("Error in converting result into json data %s", err)
					return nil, err
				}
				err = json.Unmarshal(jsonData, &resData)
				if err != nil {
					fmt.Printf("Error in unmarshalling data: %s", err)
					return nil, err
				}
				return &resData, tt.mockError
			}

			res := httptest.NewRecorder()

			// Call the handler
			getData(res, tt.requestURL)

			// Assert HTTP status
			assert.Equal(t, tt.expectedStatus, res.Code)

			// Validate response body
			body := strings.TrimSpace(res.Body.String())

			if tt.expectedStatus == http.StatusOK {
				var actual map[string]interface{}
				json.Unmarshal(res.Body.Bytes(), &actual)

				var expected map[string]interface{}
				json.Unmarshal([]byte(tt.expectedBody), &expected)

				assert.Equal(t, expected, actual)
			} else {
				assert.Contains(t, body, tt.expectedBody)
			}
		})
	}
}
