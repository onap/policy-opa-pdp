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

// Package healthcheck provides functionalities for handling health check requests.
// This package includes a function to handle HTTP requests for health checks
// and respond with the health status of the service.
package healthcheck

import (
	"encoding/json"
	"net/http"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"policy-opa-pdp/pkg/pdpattributes"
	"policy-opa-pdp/pkg/utils"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// handles HTTP requests for health checks and responds with the health status of the service.
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {

	requestId := r.Header.Get("X-ONAP-RequestID")
	var parsedUUID *uuid.UUID
	var healthCheckParams *oapicodegen.HealthcheckParams

	if requestId != "" && utils.IsValidUUID(requestId) {
		tempUUID, err := uuid.Parse(requestId)
		if err != nil {
			log.Warnf("Error Parsing the requestID: %v", err)
		} else {
			parsedUUID = &tempUUID
			healthCheckParams = &oapicodegen.HealthcheckParams{
				XONAPRequestID: (*openapi_types.UUID)(parsedUUID),
			}
			w.Header().Set("X-ONAP-RequestID", healthCheckParams.XONAPRequestID.String())
		}
	} else {
		log.Warnf("Invalid or Missing  Request ID")
		requestId = "000000000000"
		w.Header().Set("X-ONAP-RequestID", requestId)
	}
	w.Header().Set("X-LatestVersion", consts.LatestVersion)
	w.Header().Set("X-PatchVersion", consts.PatchVersion)
	w.Header().Set("X-MinorVersion", consts.MinorVersion)

	response := &oapicodegen.HealthCheckReport{
		Name:    &pdpattributes.PdpName,
		Url:     &consts.OpaPdpUrl,
		Healthy: &consts.HealtCheckStatus,
		Code:    &consts.OkCode,
		Message: &consts.HealthCheckMessage,
	}
	log.Debug("Received Health Check message")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
