// Package oapicodegen provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.16.3 DO NOT EDIT.
package oapicodegen

import (
	"time"

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

// OPADecisionRequest defines model for OPADecisionRequest.
type OPADecisionRequest struct {
	CurrentDate     *openapi_types.Date    `json:"currentDate,omitempty"`
	CurrentDateTime *time.Time             `json:"currentDateTime,omitempty"`
	CurrentTime     *string                `json:"currentTime,omitempty"`
	Input           map[string]interface{} `json:"input"`
	OnapComponent   *string                `json:"onapComponent,omitempty"`
	OnapInstance    *string                `json:"onapInstance,omitempty"`
	OnapName        *string                `json:"onapName,omitempty"`
	PolicyFilter    []string               `json:"policyFilter"`
	PolicyName      string                 `json:"policyName"`

	// TimeOffset Time offset in hours and minutes, e.g., '+02:00' or '-05:00'
	TimeOffset *string `json:"timeOffset,omitempty"`

	// TimeZone Timezone in IANA format (e.g., 'America/NewYork', 'Europe/Paris', 'UTC')
	TimeZone *string `json:"timeZone,omitempty"`
}

// OPADecisionResponse defines model for OPADecisionResponse.
type OPADecisionResponse struct {
	Output        map[string]interface{} `json:"output"`
	PolicyName    string                 `json:"policyName"`
	StatusMessage *string                `json:"statusMessage,omitempty"`
}

// StatisticsReport defines model for StatisticsReport.
type StatisticsReport struct {
	Code                  *int32 `json:"code,omitempty"`
	DecisionFailureCount  *int64 `json:"decisionFailureCount,omitempty"`
	DecisionSuccessCount  *int64 `json:"decisionSuccessCount,omitempty"`
	DeployFailureCount    *int64 `json:"deployFailureCount,omitempty"`
	DeploySuccessCount    *int64 `json:"deploySuccessCount,omitempty"`
	TotalErrorCount       *int64 `json:"totalErrorCount,omitempty"`
	TotalPoliciesCount    *int64 `json:"totalPoliciesCount,omitempty"`
	TotalPolicyTypesCount *int64 `json:"totalPolicyTypesCount,omitempty"`
	UndeployFailureCount  *int64 `json:"undeployFailureCount,omitempty"`
	UndeploySuccessCount  *int64 `json:"undeploySuccessCount,omitempty"`
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

// DecisionJSONRequestBody defines body for Decision for application/json ContentType.
type DecisionJSONRequestBody = OPADecisionRequest
