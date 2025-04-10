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

package handler

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/kafkacomm/publisher/mocks"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"testing"
)

/*
pdpUpdateMessageHandler_Message_Unmarshal_Failure2
Description: Test by sending a invalid input message which should result in a Json unmarhsal error
Input: invalid input Message by renaming params or removing certain params
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestpdpUpdateMessageHandler_Message_Unmarshal_Failure2(t *testing.T) {

	// invlaid params by mispelling a param  "source"

	messageString := `{
		"soce":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000}`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
pdpUpdateMessageHandler_Message_Unmarshal_Failure3
Description: Test by sending a invalid input message which should result in a Json unmarhsal error
Input: {}
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestpdpUpdateMessageHandler_Message_Unmarshal_Failure3(t *testing.T) {

	// invlaid params by mispelling a param  "source"

	messageString := `{
	        "soce:"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000}`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
pdpUpdateMessageHandler_Message_Unmarshal_Failure4
Description: Test by sending a invalid input message which should result in a Json unmarhsal error
Input: empty
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestpdpUpdateMessageHandler_Message_Unmarshal_Failure4(t *testing.T) {

	// invlaid params by mispelling a param  "source"

	messageString := `""`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
pdpUpdateMessageHandler_Fails_Sending_PdpUpdateResponse
Description: Test by sending a invalid attribute for pdpstate which should result in a failure in sending pdp update response
Input: invalid input config set for pdpstate
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestpdpUpdateMessageHandler_Fails_Sending_UpdateResponse(t *testing.T) {

	// invalid value set to pdpSubgroup -->empty ""
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"policiesToBeDeployed":[],
		"policiesToBeUndeployed":[],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup"
	  }`

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Error in Sending PDP Update Response"))

	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
pdpUpdateMessageHandler_Invalid_Starttimeinterval
Description: Test by sending a invalid time value attribute for pdpstate which should result in a failure in starting heartbeat interval
Input: invalid input message for pdpstate heartbeat interval
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestpdpUpdateMessageHandler_Invalid_Starttimeinterval(t *testing.T) {

	//invalid interval set to negative -1000
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":-1000,
		"policiesToBeDeployed":[],
		"policiesToBeUndeployed":[],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	  }`

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Invalid Interval Time for Heartbeat"))

	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
pdpUpdateMessageHandler_Successful_Deployment
*/
func TestpdpUpdateMessageHandler_Invalid_Deployment(t *testing.T) {
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	}`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	// Mock the policy deployment logic
	handlePolicyDeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {

		return nil, map[string]string{"zone": "1.0.0"}
	}

	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)
}

/*
pdpUpdateMessageHandler_Successful_Deployment
*/
func TestpdpUpdateMessageHandler_Successful_Deployment(t *testing.T) {
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"policiesToBeDeployed": [{"type": "onap.policies.native.opa","type_version": "1.0.0","properties": {"data": {"zone": "ewogICJ6b25lIjogewogICAgInpvbmVfYWNjZXNzX2xvZ3MiOiBbCiAgICAgIHsgImxvZ19pZCI6ICJsb2cxIiwgInRpbWVzdGFtcCI6ICIyMDI0LTExLTAxVDA5OjAwOjAwWiIsICJ6b25lX2lkIjogInpvbmVBIiwgImFjY2VzcyI6ICJncmFudGVkIiwgInVzZXIiOiAidXNlcjEiIH0sCiAgICAgIHsgImxvZ19pZCI6ICJsb2cyIiwgInRpbWVzdGFtcCI6ICIyMDI0LTExLTAxVDEwOjMwOjAwWiIsICJ6b25lX2lkIjogInpvbmVBIiwgImFjY2VzcyI6ICJkZW5pZWQiLCAidXNlciI6ICJ1c2VyMiIgfSwKICAgICAgeyAibG9nX2lkIjogImxvZzMiLCAidGltZXN0YW1wIjogIjIwMjQtMTEtMDFUMTE6MDA6MDBaIiwgInpvbmVfaWQiOiAiem9uZUIiLCAiYWNjZXNzIjogImdyYW50ZWQiLCAidXNlciI6ICJ1c2VyMyIgfQogICAgXQogIH0KfQo="},"policy": {"zone": "cGFja2FnZSB6b25lCgppbXBvcnQgcmVnby52MQoKZGVmYXVsdCBhbGxvdyA6PSBmYWxzZQoKYWxsb3cgaWYgewogICAgaGFzX3pvbmVfYWNjZXNzCiAgICBhY3Rpb25faXNfbG9nX3ZpZXcKfQoKYWN0aW9uX2lzX2xvZ192aWV3IGlmIHsKICAgICJ2aWV3IiBpbiBpbnB1dC5hY3Rpb25zCn0KCmhhc196b25lX2FjY2VzcyBjb250YWlucyBhY2Nlc3NfZGF0YSBpZiB7CiAgICBzb21lIHpvbmVfZGF0YSBpbiBkYXRhLnpvbmUuem9uZS56b25lX2FjY2Vzc19sb2dzCiAgICB6b25lX2RhdGEudGltZXN0YW1wID49IGlucHV0LnRpbWVfcGVyaW9kLmZyb20KICAgIHpvbmVfZGF0YS50aW1lc3RhbXAgPCBpbnB1dC50aW1lX3BlcmlvZC50bwogICAgem9uZV9kYXRhLnpvbmVfaWQgPT0gaW5wdXQuem9uZV9pZAogICAgYWNjZXNzX2RhdGEgOj0ge2RhdGF0eXBlOiB6b25lX2RhdGFbZGF0YXR5cGVdIHwgZGF0YXR5cGUgaW4gaW5wdXQuZGF0YXR5cGVzfQp9Cg=="}},"name": "zone","version": "1.0.0","metadata": {"policy-id": "zone","policy-version": "1.0.0"}}],
		"policiesToBeUndeployed":[],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	}`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	// Mock the policy deployment logic
	handlePolicyDeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {

		return nil, map[string]string{"zone": "1.0.0"}
	}

	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.NoError(t, err)
}

/*
pdpUpdateMessageHandler_Skipping_Deployment
*/
func TestpdpUpdateMessageHandler_Skipping_Deployment(t *testing.T) {
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"policiesToBeDeployed": [{"type": "onap.policies.native.opa","type_version": "1.0.0","properties": {"data": {"zone": "ewogICJ6b25lIjogewogICAgInpvbmVfYWNjZXNzX2xvZ3MiOiBbCiAgICAgIHsgImxvZ19pZCI6ICJsb2cxIiwgInRpbWVzdGFtcCI6ICIyMDI0LTExLTAxVDA5OjAwOjAwWiIsICJ6b25lX2lkIjogInpvbmVBIiwgImFjY2VzcyI6ICJncmFudGVkIiwgInVzZXIiOiAidXNlcjEiIH0sCiAgICAgIHsgImxvZ19pZCI6ICJsb2cyIiwgInRpbWVzdGFtcCI6ICIyMDI0LTExLTAxVDEwOjMwOjAwWiIsICJ6b25lX2lkIjogInpvbmVBIiwgImFjY2VzcyI6ICJkZW5pZWQiLCAidXNlciI6ICJ1c2VyMiIgfSwKICAgICAgeyAibG9nX2lkIjogImxvZzMiLCAidGltZXN0YW1wIjogIjIwMjQtMTEtMDFUMTE6MDA6MDBaIiwgInpvbmVfaWQiOiAiem9uZUIiLCAiYWNjZXNzIjogImdyYW50ZWQiLCAidXNlciI6ICJ1c2VyMyIgfQogICAgXQogIH0KfQo="},"policy": {"zone": "cGFja2FnZSB6b25lCgppbXBvcnQgcmVnby52MQoKZGVmYXVsdCBhbGxvdyA6PSBmYWxzZQoKYWxsb3cgaWYgewogICAgaGFzX3pvbmVfYWNjZXNzCiAgICBhY3Rpb25faXNfbG9nX3ZpZXcKfQoKYWN0aW9uX2lzX2xvZ192aWV3IGlmIHsKICAgICJ2aWV3IiBpbiBpbnB1dC5hY3Rpb25zCn0KCmhhc196b25lX2FjY2VzcyBjb250YWlucyBhY2Nlc3NfZGF0YSBpZiB7CiAgICBzb21lIHpvbmVfZGF0YSBpbiBkYXRhLnpvbmUuem9uZS56b25lX2FjY2Vzc19sb2dzCiAgICB6b25lX2RhdGEudGltZXN0YW1wID49IGlucHV0LnRpbWVfcGVyaW9kLmZyb20KICAgIHpvbmVfZGF0YS50aW1lc3RhbXAgPCBpbnB1dC50aW1lX3BlcmlvZC50bwogICAgem9uZV9kYXRhLnpvbmVfaWQgPT0gaW5wdXQuem9uZV9pZAogICAgYWNjZXNzX2RhdGEgOj0ge2RhdGF0eXBlOiB6b25lX2RhdGFbZGF0YXR5cGVdIHwgZGF0YXR5cGUgaW4gaW5wdXQuZGF0YXR5cGVzfQp9Cg=="}},"name": "zone","version": "1.0.0","metadata": {"policy-id": "zone","policy-version": "1.0.0"}}],
		"policiesToBeUndeployed":[],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	}`

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["zone"],"policy": ["zone"],"policy-id": "zone","policy-version": "1.0.0"}]}`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.NoError(t, err)
}

/*
pdpUpdateMessageHandler_FailureIn_Deployment_UnDeployment
*/
func TestpdpUpdateMessageHandler_FailureIn_Deployment_UnDeployment(t *testing.T) {
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"policiesToBeDeployed": [{"type": "onap.policies.native.opa","type_version": "1.0.0","properties": {"data": {"zone": "ewogICJ6b25lIjogewogICAgInpvbmVfYWNjZXNzX2xvZ3MiOiBbCiAgICAgIHsgImxvZ19pZCI6ICJsb2cxIiwgInRpbWVzdGFtcCI6ICIyMDI0LTExLTAxVDA5OjAwOjAwWiIsICJ6b25lX2lkIjogInpvbmVBIiwgImFjY2VzcyI6ICJncmFudGVkIiwgInVzZXIiOiAidXNlcjEiIH0sCiAgICAgIHsgImxvZ19pZCI6ICJsb2cyIiwgInRpbWVzdGFtcCI6ICIyMDI0LTExLTAxVDEwOjMwOjAwWiIsICJ6b25lX2lkIjogInpvbmVBIiwgImFjY2VzcyI6ICJkZW5pZWQiLCAidXNlciI6ICJ1c2VyMiIgfSwKICAgICAgeyAibG9nX2lkIjogImxvZzMiLCAidGltZXN0YW1wIjogIjIwMjQtMTEtMDFUMTE6MDA6MDBaIiwgInpvbmVfaWQiOiAiem9uZUIiLCAiYWNjZXNzIjogImdyYW50ZWQiLCAidXNlciI6ICJ1c2VyMyIgfQogICAgXQogIH0KfQo="},"policy": {"zone": "cGFja2FnZSB6b25lCgppbXBvcnQgcmVnby52MQoKZGVmYXVsdCBhbGxvdyA6PSBmYWxzZQoKYWxsb3cgaWYgewogICAgaGFzX3pvbmVfYWNjZXNzCiAgICBhY3Rpb25faXNfbG9nX3ZpZXcKfQoKYWN0aW9uX2lzX2xvZ192aWV3IGlmIHsKICAgICJ2aWV3IiBpbiBpbnB1dC5hY3Rpb25zCn0KCmhhc196b25lX2FjY2VzcyBjb250YWlucyBhY2Nlc3NfZGF0YSBpZiB7CiAgICBzb21lIHpvbmVfZGF0YSBpbiBkYXRhLnpvbmUuem9uZS56b25lX2FjY2Vzc19sb2dzCiAgICB6b25lX2RhdGEudGltZXN0YW1wID49IGlucHV0LnRpbWVfcGVyaW9kLmZyb20KICAgIHpvbmVfZGF0YS50aW1lc3RhbXAgPCBpbnB1dC50aW1lX3BlcmlvZC50bwogICAgem9uZV9kYXRhLnpvbmVfaWQgPT0gaW5wdXQuem9uZV9pZAogICAgYWNjZXNzX2RhdGEgOj0ge2RhdGF0eXBlOiB6b25lX2RhdGFbZGF0YXR5cGVdIHwgZGF0YXR5cGUgaW4gaW5wdXQuZGF0YXR5cGVzfQp9Cg=="}},"name": "zone","version": "1.0.0","metadata": {"policy-id": "zone","policy-version": "1.0.0"}}],
		"policiesToBeUndeployed":[{"name":"role","version":"1.0.0"}],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	}`

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["role"],"policy": ["role"],"policy-id": "role","policy-version": "1.0.0"}]}`
	// Mock the policy deployment logic
	handlePolicyDeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {

		return nil, map[string]string{"zone": "1.0.0"}
	}
	//mock the policy undeployment
	handlePolicyDeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {

		return nil, map[string]string{"role": "1.0.0"}
	}
	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.NoError(t, err)
}

/*
pdpUpdateMessageHandler_Successful_Undeployment
*/
func TestpdpUpdateMessageHandler_Successful_Undeployment(t *testing.T) {
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"policiesToBeDeployed":[],
		"policiesToBeUndeployed":[{"name":"zone","version":"1.0.0"}],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	}`

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["zone"],"policy": ["zone"],"policy-id": "zone","policy-version": "1.0.0"}]}`
	//mock the policy undeployment
	handlePolicyDeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {

		return nil, map[string]string{"zone": "1.0.0"}
	}

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.NoError(t, err)
}

/*
pdpUpdateMessageHandler_Successful_Registration
*/
func TestpdpUpdateMessageHandler_Successful_Registration(t *testing.T) {
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"policiesToBeDeployed":[],
		"policiesToBeUndeployed":[],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	}`

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(nil)
	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.NoError(t, err)
}

/*
pdpUpdateMessageHandler_Unsuccessful_Undeployment
*/
func TestpdpUpdateMessageHandler_UnSuccessful_Undeployment(t *testing.T) {
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"policiesToBeDeployed":[],
		"policiesToBeUndeployed":[{"name":"zone","version":"1.0.0"}],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	}`

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": []}`
	//mock the policy undeployment
	handlePolicyDeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {

		return []string{"Error in undeployment"}, map[string]string{}
	}

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("error in undeployment"))
	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)
}

/*
pdpUpdateMessageHandler_Partial_FailureIn_Undeployment
*/
func TestpdpUpdateMessageHandler_Partial_FailureIn_Undeployment(t *testing.T) {
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000,
		"policiesToBeDeployed":[],
		"policiesToBeUndeployed":[{"name":"zone","version":"1.0.0"},{"name":"role","version":"1.0.0"}],
		"messageName":"PDP_UPDATE",
		"requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
		"timestampMs":1730722305297,
		"name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
		"pdpGroup":"opaGroup",
		"pdpSubgroup":"opa"
	}`

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["zone"],"policy": ["zone"],"policy-id": "zone","policy-version": "1.0.0"}]}`
	//mock the policy undeployment
	handlePdpUpdateUndeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string) {

		return "", errors.New("error in undeployment"), []string{}
	}
	sendFinalResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, policies string, failures []string) error {
		assert.Equal(t, "{}", policies)
		return nil
	}
	defer func() {
		sendFinalResponseVar = sendFinalResponse
		handlePdpUpdateUndeploymentVar = handlePdpUpdateUndeployment
	}()

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("error in undeployment"))
	err := pdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)
}

func TestSendPDPStatusResponse(t *testing.T) {
	mockSender := new(MockPdpStatusSender)
	// Test case: Success with policies to be deployed
	t.Run("Success with Policies to Deploy", func(t *testing.T) {
		pdpUpdate := model.PdpUpdate{
			Source:                 "example-source-id",
			PdpHeartbeatIntervalMs: 120000,
			MessageType:            "PDP_UPDATE",
			PoliciesToBeDeployed: []model.ToscaPolicy{
				{
					Type:        "onap.policies.native.opa",
					TypeVersion: "1.0.0",
				},
			},
			PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
			Name:                   "example-name",
			TimestampMs:            1623412345678,
			PdpGroup:               "example-group",
			PdpSubgroup:            "example-subgroup",
			RequestId:              "test-request-id"}
		loggingPoliciesList := "policy1"
		mockSender.On("SendPdpStatus", mock.Anything).Return(nil) // Mock success
		err := sendPDPStatusResponse(pdpUpdate, mockSender, loggingPoliciesList, []string{})
		assert.NoError(t, err) // Expect no error

	})
	// Test case: Success with policies to undeploy
	t.Run("Success with Policies to Undeploy", func(t *testing.T) {
		pdpUpdate := model.PdpUpdate{
			Source:                 "example-source-id",
			PdpHeartbeatIntervalMs: 120000,
			MessageType:            "PDP_UPDATE",
			PoliciesToBeDeployed:   []model.ToscaPolicy{},
			PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{
				{
					Name: "policy-to-undeply",
				},
			},
			Name:        "example-name",
			TimestampMs: 1623412345678,
			PdpGroup:    "example-group",
			PdpSubgroup: "example-subgroup",
			RequestId:   "test-request-id",
		}
		loggingPoliciesList := "policy2"
		mockSender.On("SendPdpStatus", mock.Anything).Return(nil) // Mock success
		err := sendPDPStatusResponse(pdpUpdate, mockSender, loggingPoliciesList, []string{})
		assert.NoError(t, err) // Expect no error
	})
	// Test case: Fail with policies to undeploy
	t.Run("Success with Policies to Undeploy", func(t *testing.T) {
		pdpUpdate := model.PdpUpdate{
			Source:                 "example-source-id",
			PdpHeartbeatIntervalMs: 120000,
			MessageType:            "PDP_UPDATE",
			PoliciesToBeDeployed:   []model.ToscaPolicy{},
			PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{
				{
					Name: "policy-to-undeply",
				},
			},
			Name:        "example-name",
			TimestampMs: 1623412345678,
			PdpGroup:    "example-group",
			PdpSubgroup: "example-subgroup",
			RequestId:   "test-request-id",
		}
		loggingPoliciesList := "policy2"
		mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Error in sending response")) // Mock failure
		// Patching sendFailureResponse to simulate a failure
		sendSuccessResponseVar = func(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, respMessage string) error {
			return errors.New("error sending success response")
		}
		err := sendPDPStatusResponse(pdpUpdate, mockSender, loggingPoliciesList, []string{})
		assert.Error(t, err) // Expect an error since we're simulating failure in sendSuccessResponse
	})
	// Test case: Responses accordingly when both deploy and undeploy
	t.Run("Success with Both Policies", func(t *testing.T) {
		pdpUpdate := model.PdpUpdate{
			Source:                 "example-source-id",
			PdpHeartbeatIntervalMs: 120000,
			MessageType:            "PDP_UPDATE",
			PoliciesToBeDeployed: []model.ToscaPolicy{
				{
					Type:        "onap.policies.native.opa",
					TypeVersion: "1.0.0",
				},
			},
			PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{
				{
					Name: "policy-to-undeply",
				},
			},
			Name:        "example-name",
			TimestampMs: 1623412345678,
			PdpGroup:    "example-group",
			PdpSubgroup: "example-subgroup",
			RequestId:   "test-request-id",
		}
		loggingPoliciesList := "policy3, policy4"
		mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("error in response")) // Mock success
		err := sendPDPStatusResponse(pdpUpdate, mockSender, loggingPoliciesList, []string{})
		assert.Error(t, err) // Expect no error
	})
	// Test case: Failure scenario
	t.Run("Failure scenario with Error Message", func(t *testing.T) {
		pdpUpdate := model.PdpUpdate{
			Source:                 "example-source-id",
			PdpHeartbeatIntervalMs: 120000,
			MessageType:            "PDP_UPDATE",
			PoliciesToBeDeployed: []model.ToscaPolicy{
				{
					Type:        "onap.policies.native.opa",
					TypeVersion: "1.0.0",
				},
			},
			PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{
				{
					Name: "policy-to-undeply",
				},
			},
			Name:        "example-name",
			TimestampMs: 1623412345678,
			PdpGroup:    "example-group",
			PdpSubgroup: "example-subgroup",
			RequestId:   "test-request-id",
		}
		mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("sending failed")) // Simulate an error
		err := sendPDPStatusResponse(pdpUpdate, mockSender, "Some logging", []string{"Error here"})
		assert.NoError(t, err) // Expect error due to failure response
	})
}

// TestSendPDPStatusResponse function
func TestSendPDPStatusResponse_SimulateFailures(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	// Test case: Failure scenario
	pdpUpdate := model.PdpUpdate{
		Source:                 "example-source-id",
		PdpHeartbeatIntervalMs: 120000,
		MessageType:            "PDP_UPDATE",
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{
				Type:        "onap.policies.native.opa",
				TypeVersion: "1.0.0",
			},
		},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
		Name:                   "example-name",
		TimestampMs:            1623412345678,
		PdpGroup:               "example-group",
		PdpSubgroup:            "example-subgroup",
		RequestId:              "test-request-id",
	}
	// Patching sendSuccessResponse to simulate a failure
	sendSuccessResponseVar = func(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, respMessage string) error {
		return errors.New("error sending success response")
	}
	loggingPoliciesList := "policy1"
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("error")) // Mock success
	err := sendPDPStatusResponse(pdpUpdate, mockSender, loggingPoliciesList, []string{})
	assert.Error(t, err) // Expect an error since we're simulating failure in sendSuccessResponse

	// Patching sendFailureResponse to simulate a failure
	sendFailureResponseVar = func(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, respMessage error) error {
		return errors.New("error sending failure response")
	}
	err = sendPDPStatusResponse(pdpUpdate, mockSender, loggingPoliciesList, []string{"Error in Failure Response"})
	assert.Error(t, err) // Expect an error since we're simulating failure in sendSuccessResponse

}

func TestCreateBundleFunc(t *testing.T) {
}

func TesthandlePdpUpdateDeploymentVarSuccess(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	handlePolicyDeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {
		return nil, map[string]string{"policy1": "deployed"}
	}
	policymap.FormatMapOfAnyTypeVar = func(input any) (string, error) {
		return `{"policy1":"deployed"}`, nil
	}

	update := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{{Name: "policy1"}},
	}

	jsonStr, err, failureMsgs := handlePdpUpdateDeployment(update, mockSender)

	assert.NoError(t, err)
	assert.Equal(t, `{"policy1":"deployed"}`, jsonStr)
	assert.Empty(t, failureMsgs)
}

func TesthandlePdpUpdateDeploymentVarFormatError(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	handlePolicyDeploymentVar = func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {
		return nil, map[string]string{"policy1": "deployed"}
	}
	policymap.FormatMapOfAnyTypeVar = func(input any) (string, error) {
		return "", errors.New("formatting error")
	}
	sendFailureResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, err error) error {
		return nil
	}

	update := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{{Name: "policy1"}},
	}

	jsonStr, err, failureMsgs := handlePdpUpdateDeployment(update, mockSender)

	assert.NoError(t, err)
	assert.Equal(t, "", jsonStr)
	assert.Contains(t, failureMsgs[0], "Internal Map Error")
}

func TesthandlePdpUpdateUndeploymentVarSuccess(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	handlePolicyUndeploymentVar = func(update model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {
		return nil, map[string]string{"policy1": "undeployed"}
	}
	policymap.FormatMapOfAnyTypeVar = func(input any) (string, error) {
		return `{"policy1":"undeployed"}`, nil
	}

	update := model.PdpUpdate{
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{{Name: "policy1"}},
	}

	jsonStr, err, failureMsgs := handlePdpUpdateUndeployment(update, mockSender)

	assert.NoError(t, err)
	assert.Equal(t, `{"policy1":"undeployed"}`, jsonStr)
	assert.Empty(t, failureMsgs)
}

func TesthandlePdpUpdateUndeploymentVarFormatError(t *testing.T) {
	mockSender := new(MockPdpStatusSender)

	handlePolicyUndeploymentVar = func(update model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {
		return nil, map[string]string{"policy1": "undeployed"}
	}
	policymap.FormatMapOfAnyTypeVar = func(input any) (string, error) {
		return "", errors.New("formatting error")
	}
	sendFailureResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, err error) error {
		return nil
	}

	update := model.PdpUpdate{
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{{Name: "policy1"}},
	}

	jsonStr, err, failureMsgs := handlePdpUpdateUndeployment(update, mockSender)

	assert.NoError(t, err)
	assert.Equal(t, "", jsonStr)
	assert.Contains(t, failureMsgs[0], "Internal Map Error")
}

func Test_UnmarshalFails(t *testing.T) {
	msg := []byte(`invalid json`)
	mockPublisher := new(mocks.PdpStatusSender)

	var called bool
	sendFailureResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, err error) error {
		called = true
		return nil
	}
	defer func() { sendFailureResponseVar = sendFailureResponse }()

	err := pdpUpdateMessageHandler(msg, mockPublisher)
	assert.Error(t, err)
	assert.True(t, called)
}

func Test_ValidationFails(t *testing.T) {
	msg := []byte(`{"pdpSubgroup":"test","pdpHeartbeatIntervalMs":3000}`)
	mockPublisher := new(mocks.PdpStatusSender)

	utils.ValidateFieldsStructsVar = func(pdpUpdate model.PdpUpdate) error {
		return errors.New("validation error")
	}
	defer func() { utils.ValidateFieldsStructsVar = utils.ValidateFieldsStructs }()

	var called bool
	sendFailureResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, err error) error {
		called = true
		return nil
	}
	defer func() { sendFailureResponseVar = sendFailureResponse }()

	err := pdpUpdateMessageHandler(msg, mockPublisher)
	assert.Error(t, err)
	assert.True(t, called)
}

func Test_DeploymentHandlerFails(t *testing.T) {
	msg := []byte(`{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed": [{"type": "onap.policies.native.opa","type_version": "1.0.0","properties": {"data": {"zone": "ewogICJ6b25lIjogewogICAgInpvbmVfYWNjZXNzX2xvZ3MiOiBbCiAgICAgIHsgImxvZ19pZCI6ICJsb2cxIiwgInRpbWVzdGFtcCI6ICIyMDI0LTExLTAxVDA5OjAwOjAwWiIsICJ6b25lX2lkIjogInpvbmVBIiwgImFjY2VzcyI6ICJncmFudGVkIiwgInVzZXIiOiAidXNlcjEiIH0sCiAgICAgIHsgImxvZ19pZCI6ICJsb2cyIiwgInRpbWVzdGFtcCI6ICIyMDI0LTExLTAxVDEwOjMwOjAwWiIsICJ6b25lX2lkIjogInpvbmVBIiwgImFjY2VzcyI6ICJkZW5pZWQiLCAidXNlciI6ICJ1c2VyMiIgfSwKICAgICAgeyAibG9nX2lkIjogImxvZzMiLCAidGltZXN0YW1wIjogIjIwMjQtMTEtMDFUMTE6MDA6MDBaIiwgInpvbmVfaWQiOiAiem9uZUIiLCAiYWNjZXNzIjogImdyYW50ZWQiLCAidXNlciI6ICJ1c2VyMyIgfQogICAgXQogIH0KfQo="},"policy": {"zone": "cGFja2FnZSB6b25lCgppbXBvcnQgcmVnby52MQoKZGVmYXVsdCBhbGxvdyA6PSBmYWxzZQoKYWxsb3cgaWYgewogICAgaGFzX3pvbmVfYWNjZXNzCiAgICBhY3Rpb25faXNfbG9nX3ZpZXcKfQoKYWN0aW9uX2lzX2xvZ192aWV3IGlmIHsKICAgICJ2aWV3IiBpbiBpbnB1dC5hY3Rpb25zCn0KCmhhc196b25lX2FjY2VzcyBjb250YWlucyBhY2Nlc3NfZGF0YSBpZiB7CiAgICBzb21lIHpvbmVfZGF0YSBpbiBkYXRhLnpvbmUuem9uZS56b25lX2FjY2Vzc19sb2dzCiAgICB6b25lX2RhdGEudGltZXN0YW1wID49IGlucHV0LnRpbWVfcGVyaW9kLmZyb20KICAgIHpvbmVfZGF0YS50aW1lc3RhbXAgPCBpbnB1dC50aW1lX3BlcmlvZC50bwogICAgem9uZV9kYXRhLnpvbmVfaWQgPT0gaW5wdXQuem9uZV9pZAogICAgYWNjZXNzX2RhdGEgOj0ge2RhdGF0eXBlOiB6b25lX2RhdGFbZGF0YXR5cGVdIHwgZGF0YXR5cGUgaW4gaW5wdXQuZGF0YXR5cGVzfQp9Cg=="}},"name": "zone","version": "1.0.0","metadata": {"policy-id": "zone","policy-version": "1.0.0"}}],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_UPDATE",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	}`)

	policymap.LastDeployedPolicies = `{"deployed_policies_dict": [{"data": ["zone"],"policy": ["zone"],"policy-id": "zone","policy-version": "1.0.0"}]}`
	mockPublisher := new(mocks.PdpStatusSender)
	mockPublisher.On("SendPdpStatus", mock.Anything).Return(nil)
	sendFinalResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, policies string, failures []string) error {
		assert.Equal(t, "{}", policies)
		return nil
	}
	defer func() {
		sendFinalResponseVar = sendFinalResponse
	}()
	err := pdpUpdateMessageHandler(msg, mockPublisher)
	assert.NoError(t, err)
}

func Test_UndeploymentHandlerFails(t *testing.T) {
	msg := []byte(`{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[{"name":"zone","version":"1.0.0"}],
	        "messageName":"PDP_UPDATE",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	}`)
	policymap.LastDeployedPolicies = `{"deployed_policies_dict": []}`
	mockPublisher := new(mocks.PdpStatusSender)
	handlePdpUpdateUndeploymentVar = func(update model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string) {
		return "", errors.New("undeployment error"), []string{}
	}
	defer func() {
		handlePdpUpdateDeploymentVar = handlePdpUpdateDeployment
		handlePdpUpdateUndeploymentVar = handlePdpUpdateUndeployment
	}()
	mockPublisher.On("SendPdpStatus", mock.Anything).Return(errors.New("undeployment error"))
	err := pdpUpdateMessageHandler(msg, mockPublisher)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "undeployment error")
}

func Test_SuccessFlow(t *testing.T) {
	msg := []byte(`{
	        "source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
	        "pdpHeartbeatIntervalMs":120000,
	        "policiesToBeDeployed":[],
	        "policiesToBeUndeployed":[],
	        "messageName":"PDP_UPDATE",
	        "requestId":"41c117db-49a0-40b0-8586-5580d042d0a1",
	        "timestampMs":1730722305297,
	        "name":"opa-21cabb3e-f652-4ca6-b498-a77e62fcd059",
	        "pdpGroup":"opaGroup",
	        "pdpSubgroup":"opa"
	         }`)

	mockPublisher := new(mocks.PdpStatusSender)

	handlePdpUpdateDeploymentVar = func(update model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string) {
		return "dep1", nil, []string{}
	}
	handlePdpUpdateUndeploymentVar = func(update model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string) {
		return "undep1", nil, []string{}
	}
	sendFinalResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, policies string, failures []string) error {
		assert.Equal(t, "dep1,undep1", policies)
		return nil
	}

	defer func() {
		handlePdpUpdateDeploymentVar = handlePdpUpdateDeployment
		handlePdpUpdateUndeploymentVar = handlePdpUpdateUndeployment
		sendFinalResponseVar = sendFinalResponse
	}()
	mockPublisher.On("SendPdpStatus", mock.Anything).Return(nil)
	err := pdpUpdateMessageHandler(msg, mockPublisher)
	assert.NoError(t, err)
}

func TestSendPDPStatusFailureResponse_Mocked(t *testing.T) {
	original := sendFailureResponseVar
	defer func() { sendFailureResponseVar = original }() // restore after test

	called := false
	sendFailureResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, msg error) error {
		called = true
		assert.Equal(t, "PDP Update Failed: [mock fail]", msg.Error())
		return nil
	}

	err := sendPDPStatusFailureResponse(model.PdpUpdate{}, nil, "mockPolicy", []string{"mock fail"})
	assert.NoError(t, err)
	assert.True(t, called, "sendFailureResponseVar should be called")
}

func TestSendPDPStatusSuccessResponse_Mocked(t *testing.T) {
	original := sendSuccessResponseVar
	defer func() { sendSuccessResponseVar = original }() // restore after test

	called := false
	sendSuccessResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, msg string) error {
		called = true
		assert.Equal(t, "PDP Update Successful for all policies: p1,p2", msg)
		return nil
	}

	update := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{
				Type:        "onap.policies.native.opa",
				TypeVersion: "1.0.0",
			},
		},

		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{
			{
				Name: "policy-to-undeply",
			},
		},
	}

	err := sendPDPStatusSuccessResponse(update, nil, "p1,p2")
	assert.NoError(t, err)
	assert.True(t, called, "sendSuccessResponseVar should be called")
}

func TestSendFinalResponse_MockedSendPDPStatusResponse_Success(t *testing.T) {
	defer func() { sendPDPStatusResponseFunc = sendPDPStatusResponse }() // Reset after test

	mockSender := new(mocks.PdpStatusSender)
	pdpUpdate := &model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{{Name: "TestPolicy"}},
	}

	// Override the global function for testing
	sendPDPStatusResponseFunc = func(update model.PdpUpdate, p publisher.PdpStatusSender, loggingPoliciesList string, failureMessages []string) error {
		return nil
	}

	err := sendFinalResponse(mockSender, pdpUpdate, "TestPolicy", nil)
	assert.NoError(t, err)
}

func TestSendFinalResponse_MockedSendPDPStatusResponse_Failure(t *testing.T) {
	defer func() { sendPDPStatusResponseFunc = sendPDPStatusResponse }() // Reset after test

	mockSender := new(mocks.PdpStatusSender)
	pdpUpdate := &model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{{Name: "FailPolicy"}},
	}

	sendPDPStatusResponseFunc = func(update model.PdpUpdate, p publisher.PdpStatusSender, loggingPoliciesList string, failureMessages []string) error {
		return errors.New("mock failure")
	}

	err := sendFinalResponse(mockSender, pdpUpdate, "FailPolicy", nil)
	assert.Error(t, err)
	assert.Equal(t, "mock failure", err.Error())
}

func TestHandlePdpUpdateUndeployment_WithFailureMessage(t *testing.T) {
	defer func() {
		handlePolicyUndeploymentVar = handlePolicyUndeployment
		policymap.FormatMapOfAnyTypeVar = policymap.FormatMapofAnyType
	}()

	mockSender := new(mocks.PdpStatusSender)
	update := model.PdpUpdate{
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{{Name: "Policy1"}},
	}

	handlePolicyUndeploymentVar = func(update model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {

		return []string{"UndeployError"}, map[string]string{"Policy1": "undeployed"}
	}

	policymap.FormatMapOfAnyTypeVar = func(data interface{}) (string, error) {
		return "Policy1", nil
	}

	json, err, failures := handlePdpUpdateUndeployment(update, mockSender)

	assert.NoError(t, err)
	assert.Equal(t, "Policy1", json)
	assert.Contains(t, failures[0], "UnDeployment Errors:UndeployError")
}

func TestHandlePdpUpdateUndeployment_SendFailureResponseFails(t *testing.T) {
	defer func() {
		handlePolicyUndeploymentVar = handlePolicyUndeployment
		policymap.FormatMapOfAnyTypeVar = policymap.FormatMapofAnyType
		sendFailureResponseVar = sendFailureResponse
	}()

	mockSender := new(mocks.PdpStatusSender)
	update := model.PdpUpdate{
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{{Name: "Policy1"}},
	}

	handlePolicyUndeploymentVar = func(update model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {
		return nil, map[string]string{"Policy1": "undeployed"}
	}

	policymap.FormatMapOfAnyTypeVar = func(data interface{}) (string, error) {
		return "", errors.New("mock format error")
	}

	sendFailureResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, err error) error {
		return errors.New("send failed")
	}

	json, err, failures := handlePdpUpdateUndeployment(update, mockSender)

	assert.Error(t, err)
	assert.Equal(t, "send failed", err.Error())
	assert.Empty(t, json)
	assert.NotEmpty(t, failures)
}

func TestSendSuccessResponse_Success(t *testing.T) {
	original := publisher.SendPdpUpdateResponseVar
	defer func() { publisher.SendPdpUpdateResponseVar = original }()

	mockSender := new(mocks.PdpStatusSender)
	update := &model.PdpUpdate{RequestId: "123"}

	publisher.SendPdpUpdateResponseVar = func(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, message string) error {
		assert.Equal(t, "123", pdpUpdate.RequestId)
		assert.Equal(t, "Success", message)
		return nil
	}

	err := sendSuccessResponse(mockSender, update, "Success")
	assert.NoError(t, err)
}

func TestSendSuccessResponse_Error(t *testing.T) {
	original := publisher.SendPdpUpdateResponseVar
	defer func() { publisher.SendPdpUpdateResponseVar = original }()

	mockSender := new(mocks.PdpStatusSender)
	update := &model.PdpUpdate{RequestId: "123"}

	publisher.SendPdpUpdateResponseVar = func(p publisher.PdpStatusSender, pdpUpdate *model.PdpUpdate, message string) error {
		return errors.New("mock error")
	}

	err := sendSuccessResponse(mockSender, update, "test")
	assert.Error(t, err)
	assert.Equal(t, "mock error", err.Error())
}

func TestPdpUpdateMessageHandler_UnmarshalError_SendFailureFails(t *testing.T) {
	defer func() { sendFailureResponseVar = sendFailureResponse }()

	mockSender := new(mocks.PdpStatusSender)
	invalidMessage := []byte(`{invalid json}`)

	sendFailureResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, err error) error {
		return errors.New("send failure after unmarshal error")
	}

	err := pdpUpdateMessageHandler(invalidMessage, mockSender)
	assert.Error(t, err)
	assert.EqualError(t, err, "send failure after unmarshal error")
}

func TestPdpUpdateMessageHandler_ValidationError_SendFailureFails(t *testing.T) {
	defer func() {
		sendFailureResponseVar = sendFailureResponse
		utils.ValidateFieldsStructsVar = utils.ValidateFieldsStructs
	}()

	mockSender := new(mocks.PdpStatusSender)
	message := []byte(`{"PdpSubgroup":"test", "PdpHeartbeatIntervalMs":30000}`)

	utils.ValidateFieldsStructsVar = func(update model.PdpUpdate) error {
		return errors.New("mock validation error")
	}

	sendFailureResponseVar = func(p publisher.PdpStatusSender, update *model.PdpUpdate, err error) error {
		return errors.New("send failure after validation")
	}

	err := pdpUpdateMessageHandler(message, mockSender)
	assert.Error(t, err)
	assert.EqualError(t, err, "send failure after validation")
}

func TestPdpUpdateMessageHandler_DeploymentFails(t *testing.T) {
	defer func() {
		handlePdpUpdateDeploymentVar = handlePdpUpdateDeployment
		handlePdpUpdateUndeploymentVar = handlePdpUpdateUndeployment
		utils.ValidateFieldsStructsVar = utils.ValidateFieldsStructs
		sendFinalResponseVar = sendFinalResponse
	}()

	mockSender := new(mocks.PdpStatusSender)
	message := []byte(`{"PdpSubgroup":"test", "PdpHeartbeatIntervalMs":30000}`)

	utils.ValidateFieldsStructsVar = func(update model.PdpUpdate) error {
		return nil
	}

	handlePdpUpdateDeploymentVar = func(update model.PdpUpdate, p publisher.PdpStatusSender) (string, error, []string) {
		return "", errors.New("deployment error"), []string{"failure"}
	}

	err := pdpUpdateMessageHandler(message, mockSender)
	assert.Error(t, err)
	assert.EqualError(t, err, "deployment error")
}

func TestHandlePdpUpdateDeployment_WithDeploymentFailures(t *testing.T) {
	defer func() {
		handlePolicyDeploymentVar = handlePolicyDeployment
		policymap.FormatMapOfAnyTypeVar = policymap.FormatMapofAnyType
	}()

	mockSender := new(mocks.PdpStatusSender)

	handlePolicyDeploymentVar = func(update model.PdpUpdate, sender publisher.PdpStatusSender) ([]string, map[string]string) {
		return []string{"failedPolicy1"}, map[string]string{"successPolicy": "test"}
	}

	policymap.FormatMapOfAnyTypeVar = func(data interface{}) (string, error) {
		return `{"successPolicy":"test"}`, nil
	}

	update := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{{Name: "test-policy"}},
	}

	mapJson, err, failures := handlePdpUpdateDeployment(update, mockSender)
	assert.NoError(t, err)
	assert.Contains(t, failures[0], "Deployment Errors")
	assert.Contains(t, mapJson, `"successPolicy":"test"`)
}

func TestHandlePdpUpdateDeployment_FormatMapFails(t *testing.T) {
	defer func() {
		handlePolicyDeploymentVar = handlePolicyDeployment
		policymap.FormatMapOfAnyTypeVar = policymap.FormatMapofAnyType
		sendFailureResponseVar = sendFailureResponse
	}()

	mockSender := new(mocks.PdpStatusSender)

	handlePolicyDeploymentVar = func(update model.PdpUpdate, sender publisher.PdpStatusSender) ([]string, map[string]string) {
		return nil, map[string]string{"some": "policy"}
	}

	policymap.FormatMapOfAnyTypeVar = func(data interface{}) (string, error) {
		return "", errors.New("mock formatting error")
	}

	sendFailureResponseVar = func(sender publisher.PdpStatusSender, update *model.PdpUpdate, err error) error {
		return nil
	}

	update := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{{Name: "test-policy"}},
	}

	mapJson, err, failures := handlePdpUpdateDeployment(update, mockSender)
	assert.NoError(t, err)
	assert.Equal(t, "", mapJson)
	assert.Contains(t, failures[0], "Internal Map Error")
}
