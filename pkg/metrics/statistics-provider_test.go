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
//

package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchCurrentStatistics(t *testing.T) {

	IndeterminantDecisionsCount = 10
	PermitDecisionsCount = 15
	DenyDecisionsCount = 20
	TotalErrorCount = 5

	// Create a new HTTP request
	req := httptest.NewRequest(http.MethodGet, "/statistics", nil)
	// Create a response recorder to capture the response
	res := httptest.NewRecorder()

	// Call the function under test
	FetchCurrentStatistics(res, req)

	// Verify the status code
	assert.Equal(t, http.StatusOK, res.Code)

	// Verify the response headers
	assert.Equal(t, "application/json", res.Header().Get("Content-Type"))

	var statReport oapicodegen.StatisticsReport
	err := json.Unmarshal(res.Body.Bytes(), &statReport)
	assert.NoError(t, err)

	// Verify the response body
	assert.Equal(t, int64(10), *statReport.IndeterminantDecisionsCount)
	assert.Equal(t, int64(15), *statReport.PermitDecisionsCount)
	assert.Equal(t, int64(20), *statReport.DenyDecisionsCount)
	assert.Equal(t, int64(5), *statReport.TotalErrorCount)
	assert.Equal(t, int64(0), *statReport.TotalPoliciesCount)
	assert.Equal(t, int64(1), *statReport.TotalPolicyTypesCount)
	assert.Equal(t, int64(0), *statReport.DeployFailureCount)
	assert.Equal(t, int64(0), *statReport.DeploySuccessCount)
	assert.Equal(t, int64(0), *statReport.UndeployFailureCount)
	assert.Equal(t, int64(0), *statReport.UndeploySuccessCount)

	assert.Equal(t, int32(200), *statReport.Code)
}

func TestFetchCurrentStatistics_ValidRequestID(t *testing.T) {

	validUUID := "123e4567-e89b-12d3-a456-426614174000"

	req := httptest.NewRequest(http.MethodGet, "/statistics", nil)

	req.Header.Set("X-ONAP-RequestID", validUUID)

	res := httptest.NewRecorder()

	// Call the function under test

	FetchCurrentStatistics(res, req)

	assert.Equal(t, validUUID, res.Header().Get("X-ONAP-RequestID"))

	assert.Equal(t, http.StatusOK, res.Code)

}
