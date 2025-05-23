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

// Handles an HTTP request to fetch the current system statistics
// and error counts into a structured response and sends it back to the client in JSON format.
package metrics

import (
	"encoding/json"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"net/http"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/utils"
)

func FetchCurrentStatistics(res http.ResponseWriter, req *http.Request) {

	requestId := req.Header.Get(consts.RequestId)
	var parsedUUID *uuid.UUID
	var statisticsParams *oapicodegen.StatisticsParams

	if requestId != "" && utils.IsValidUUID(requestId) {
		tempUUID, err := uuid.Parse(requestId)
		if err != nil {
			log.Warnf("Error Parsing the requestID: %v", err)
		} else {
			parsedUUID = &tempUUID
			statisticsParams = &oapicodegen.StatisticsParams{
				XONAPRequestID: (*openapi_types.UUID)(parsedUUID),
			}
			res.Header().Set(consts.RequestId, statisticsParams.XONAPRequestID.String())
		}
	} else {
		log.Warnf("Invalid or Missing  Request ID")
		requestId = "000000000000"
		res.Header().Set(consts.RequestId, requestId)
	}

	var statReport oapicodegen.StatisticsReport

	statReport.DecisionSuccessCount = totalDecisionSuccessCountRef()
	statReport.DecisionFailureCount = TotalDecisionFailureCountRef()
	statReport.TotalErrorCount = totalErrorCountRef()
	statReport.DeployFailureCount = totalDeployFailureCountRef()
	statReport.DeploySuccessCount = totalDeploySuccessCountRef()
	statReport.UndeployFailureCount = totalUndeployFailureCountRef()
	statReport.UndeploySuccessCount = totalUndeploySuccessCountRef()
	statReport.TotalPoliciesCount = totalPoliciesCountRef()
	statReport.DynamicDataUpdateFailureCount = totalDynamicDataUpdateFailureCountRef()
	statReport.DynamicDataUpdateSuccessCount = totalDynamicDataUpdateSuccessCountRef()

	// not implemented hardcoding the values to zero
	// will be implemeneted in phase-2
	onevalue := int64(1)
	statReport.TotalPolicyTypesCount = &onevalue

	value := int32(200)
	statReport.Code = &value

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(res).Encode(statReport); err != nil {
		log.Errorf("Failed to encode JSON response: %v", err)
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
