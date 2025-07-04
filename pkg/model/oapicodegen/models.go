// Package oapicodegen provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.16.3 DO NOT EDIT.
package oapicodegen

import (
	"encoding/json"
	"time"

	"github.com/oapi-codegen/runtime"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

const (
	BasicAuthScopes = "basicAuth.Scopes"
)

// Defines values for ErrorResponseResponseCode.
const (
	BadRequest        ErrorResponseResponseCode = "bad_request"
	EvaluationError   ErrorResponseResponseCode = "evaluation_error"
	InternalError     ErrorResponseResponseCode = "internal_error"
	InvalidOperation  ErrorResponseResponseCode = "invalid_operation"
	InvalidParameter  ErrorResponseResponseCode = "invalid_parameter"
	OpaUndefinedError ErrorResponseResponseCode = "opa_undefined_error"
	ResourceConflict  ErrorResponseResponseCode = "resource_conflict"
	ResourceNotFound  ErrorResponseResponseCode = "resource_not_found"
	Unauthorized      ErrorResponseResponseCode = "unauthorized"
	UndefinedDocument ErrorResponseResponseCode = "undefined_document"
)

// ErrorResponse defines model for ErrorResponse.
type ErrorResponse struct {
	ErrorMessage *string                    `json:"errorMessage,omitempty"`
	PolicyName   *string                    `json:"policyName,omitempty"`
	ResponseCode *ErrorResponseResponseCode `json:"responseCode,omitempty"`
}

// ErrorResponseResponseCode defines model for ErrorResponse.ResponseCode.
type ErrorResponseResponseCode string

// HealthCheckReport defines model for HealthCheckReport.
type HealthCheckReport struct {
	Code    *int32  `json:"code,omitempty"`
	Healthy *bool   `json:"healthy,omitempty"`
	Message *string `json:"message,omitempty"`
	Name    *string `json:"name,omitempty"`
	Url     *string `json:"url,omitempty"`
}

// OPADataResponse defines model for OPADataResponse.
type OPADataResponse struct {
	Data *OPADataResponse_Data `json:"data,omitempty"`
}

// OPADataResponseData0 defines model for .
type OPADataResponseData0 = interface{}

// OPADataResponseData1 defines model for .
type OPADataResponseData1 map[string]interface{}

// OPADataResponse_Data defines model for OPADataResponse.Data.
type OPADataResponse_Data struct {
	union json.RawMessage
}

// OPADataUpdateRequest defines model for OPADataUpdateRequest.
type OPADataUpdateRequest struct {
	CurrentDate     *openapi_types.Date      `json:"currentDate,omitempty"`
	CurrentDateTime *time.Time               `json:"currentDateTime,omitempty"`
	CurrentTime     *string                  `json:"currentTime,omitempty"`
	Data            []map[string]interface{} `json:"data"`
	OnapComponent   *string                  `json:"onapComponent,omitempty"`
	OnapInstance    *string                  `json:"onapInstance,omitempty"`
	OnapName        *string                  `json:"onapName,omitempty"`
	PolicyName      string                   `json:"policyName"`

	// TimeOffset Time offset in hours and minutes, e.g., '+02:00' or '-05:00'
	TimeOffset *string `json:"timeOffset,omitempty"`

	// TimeZone Timezone in IANA format (e.g., 'America/NewYork', 'Europe/Paris', 'UTC')
	TimeZone *string `json:"timeZone,omitempty"`
}

// OPADecisionRequest defines model for OPADecisionRequest.
type OPADecisionRequest struct {
	CurrentDate     *openapi_types.Date      `json:"currentDate,omitempty"`
	CurrentDateTime *time.Time               `json:"currentDateTime,omitempty"`
	CurrentTime     *string                  `json:"currentTime,omitempty"`
	Input           OPADecisionRequest_Input `json:"input"`
	OnapComponent   *string                  `json:"onapComponent,omitempty"`
	OnapInstance    *string                  `json:"onapInstance,omitempty"`
	OnapName        *string                  `json:"onapName,omitempty"`
	PolicyFilter    []string                 `json:"policyFilter"`
	PolicyName      string                   `json:"policyName"`

	// TimeOffset Time offset in hours and minutes, e.g., '+02:00' or '-05:00'
	TimeOffset *string `json:"timeOffset,omitempty"`

	// TimeZone Timezone in IANA format (e.g., 'America/NewYork', 'Europe/Paris', 'UTC')
	TimeZone *string `json:"timeZone,omitempty"`
}

// OPADecisionRequestInput0 defines model for .
type OPADecisionRequestInput0 = interface{}

// OPADecisionRequestInput1 defines model for .
type OPADecisionRequestInput1 map[string]interface{}

// OPADecisionRequest_Input defines model for OPADecisionRequest.Input.
type OPADecisionRequest_Input struct {
	union json.RawMessage
}

// OPADecisionResponse defines model for OPADecisionResponse.
type OPADecisionResponse struct {
	Output        *map[string]interface{} `json:"output,omitempty"`
	PolicyName    *string                 `json:"policyName,omitempty"`
	StatusMessage *string                 `json:"statusMessage,omitempty"`
}

// StatisticsReport defines model for StatisticsReport.
type StatisticsReport struct {
	Code                          *int32 `json:"code,omitempty"`
	DecisionFailureCount          *int64 `json:"decisionFailureCount,omitempty"`
	DecisionSuccessCount          *int64 `json:"decisionSuccessCount,omitempty"`
	DeployFailureCount            *int64 `json:"deployFailureCount,omitempty"`
	DeploySuccessCount            *int64 `json:"deploySuccessCount,omitempty"`
	DynamicDataUpdateFailureCount *int64 `json:"dynamicDataUpdateFailureCount,omitempty"`
	DynamicDataUpdateSuccessCount *int64 `json:"dynamicDataUpdateSuccessCount,omitempty"`
	TotalErrorCount               *int64 `json:"totalErrorCount,omitempty"`
	TotalPoliciesCount            *int64 `json:"totalPoliciesCount,omitempty"`
	TotalPolicyTypesCount         *int64 `json:"totalPolicyTypesCount,omitempty"`
	UndeployFailureCount          *int64 `json:"undeployFailureCount,omitempty"`
	UndeploySuccessCount          *int64 `json:"undeploySuccessCount,omitempty"`
}

// DataGetParams defines parameters for DataGet.
type DataGetParams struct {
	// XONAPRequestID RequestID for http transaction
	XONAPRequestID *openapi_types.UUID `json:"X-ONAP-RequestID,omitempty"`
}

// PatchdataParams defines parameters for Patchdata.
type PatchdataParams struct {
	// XONAPRequestID RequestID for http transaction
	XONAPRequestID *openapi_types.UUID `json:"X-ONAP-RequestID,omitempty"`
}

// DecisionParams defines parameters for Decision.
type DecisionParams struct {
	// XONAPRequestID RequestID for http transaction
	XONAPRequestID *openapi_types.UUID `json:"X-ONAP-RequestID,omitempty"`
}

// HealthcheckParams defines parameters for Healthcheck.
type HealthcheckParams struct {
	// XONAPRequestID RequestID for http transaction
	XONAPRequestID *openapi_types.UUID `json:"X-ONAP-RequestID,omitempty"`
}

// StatisticsParams defines parameters for Statistics.
type StatisticsParams struct {
	// XONAPRequestID RequestID for http transaction
	XONAPRequestID *openapi_types.UUID `json:"X-ONAP-RequestID,omitempty"`
}

// PatchdataJSONRequestBody defines body for Patchdata for application/json ContentType.
type PatchdataJSONRequestBody = OPADataUpdateRequest

// DecisionJSONRequestBody defines body for Decision for application/json ContentType.
type DecisionJSONRequestBody = OPADecisionRequest

// AsOPADataResponseData0 returns the union data inside the OPADataResponse_Data as a OPADataResponseData0
func (t OPADataResponse_Data) AsOPADataResponseData0() (OPADataResponseData0, error) {
	var body OPADataResponseData0
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromOPADataResponseData0 overwrites any union data inside the OPADataResponse_Data as the provided OPADataResponseData0
func (t *OPADataResponse_Data) FromOPADataResponseData0(v OPADataResponseData0) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeOPADataResponseData0 performs a merge with any union data inside the OPADataResponse_Data, using the provided OPADataResponseData0
func (t *OPADataResponse_Data) MergeOPADataResponseData0(v OPADataResponseData0) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(t.union, b)
	t.union = merged
	return err
}

// AsOPADataResponseData1 returns the union data inside the OPADataResponse_Data as a OPADataResponseData1
func (t OPADataResponse_Data) AsOPADataResponseData1() (OPADataResponseData1, error) {
	var body OPADataResponseData1
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromOPADataResponseData1 overwrites any union data inside the OPADataResponse_Data as the provided OPADataResponseData1
func (t *OPADataResponse_Data) FromOPADataResponseData1(v OPADataResponseData1) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeOPADataResponseData1 performs a merge with any union data inside the OPADataResponse_Data, using the provided OPADataResponseData1
func (t *OPADataResponse_Data) MergeOPADataResponseData1(v OPADataResponseData1) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(t.union, b)
	t.union = merged
	return err
}

func (t OPADataResponse_Data) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}

func (t *OPADataResponse_Data) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}

// AsOPADecisionRequestInput0 returns the union data inside the OPADecisionRequest_Input as a OPADecisionRequestInput0
func (t OPADecisionRequest_Input) AsOPADecisionRequestInput0() (OPADecisionRequestInput0, error) {
	var body OPADecisionRequestInput0
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromOPADecisionRequestInput0 overwrites any union data inside the OPADecisionRequest_Input as the provided OPADecisionRequestInput0
func (t *OPADecisionRequest_Input) FromOPADecisionRequestInput0(v OPADecisionRequestInput0) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeOPADecisionRequestInput0 performs a merge with any union data inside the OPADecisionRequest_Input, using the provided OPADecisionRequestInput0
func (t *OPADecisionRequest_Input) MergeOPADecisionRequestInput0(v OPADecisionRequestInput0) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(t.union, b)
	t.union = merged
	return err
}

// AsOPADecisionRequestInput1 returns the union data inside the OPADecisionRequest_Input as a OPADecisionRequestInput1
func (t OPADecisionRequest_Input) AsOPADecisionRequestInput1() (OPADecisionRequestInput1, error) {
	var body OPADecisionRequestInput1
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromOPADecisionRequestInput1 overwrites any union data inside the OPADecisionRequest_Input as the provided OPADecisionRequestInput1
func (t *OPADecisionRequest_Input) FromOPADecisionRequestInput1(v OPADecisionRequestInput1) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeOPADecisionRequestInput1 performs a merge with any union data inside the OPADecisionRequest_Input, using the provided OPADecisionRequestInput1
func (t *OPADecisionRequest_Input) MergeOPADecisionRequestInput1(v OPADecisionRequestInput1) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(t.union, b)
	t.union = merged
	return err
}

func (t OPADecisionRequest_Input) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}

func (t *OPADecisionRequest_Input) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}
