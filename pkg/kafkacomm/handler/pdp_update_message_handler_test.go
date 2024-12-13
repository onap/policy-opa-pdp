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
//

package handler

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"policy-opa-pdp/pkg/kafkacomm/publisher/mocks"
	"testing"
)

/*
PdpUpdateMessageHandler_success
Description: Test by sending a valid input message for pdp update
Input: valid input
Expected Output: PDP Update Message should be sent sucessfully.
*/
func TestPdpUpdateMessageHandler_Success(t *testing.T) {

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

	err := PdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.NoError(t, err)

}

/*
PdpUpdateMessageHandler_Message_Unmarshal_Failure1
Description: Test by sending a invalid input message which should result in a Json unmarhsal error
Input: invalid input Message by renaming params or removing certain params
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestPdpUpdateMessageHandler_Message_Unmarshal_Failure1(t *testing.T) {

	// sending only source parameter in the message string
	messageString := `{
		"source":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0"}`

	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

	err := PdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
PdpUpdateMessageHandler_Message_Unmarshal_Failure2
Description: Test by sending a invalid input message which should result in a Json unmarhsal error
Input: invalid input Message by renaming params or removing certain params
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestPdpUpdateMessageHandler_Message_Unmarshal_Failure2(t *testing.T) {

	// invlaid params by mispelling a param  "source"

	messageString := `{
		"soce":"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
		"pdpHeartbeatIntervalMs":120000}`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

	err := PdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
PdpUpdateMessageHandler_Message_Unmarshal_Failure3
Description: Test by sending a invalid input message which should result in a Json unmarhsal error
Input: {}
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestPdpUpdateMessageHandler_Message_Unmarshal_Failure3(t *testing.T) {

	// invlaid params by mispelling a param  "source"

	messageString := `{
                "soce:"pap-c17b4dbc-3278-483a-ace9-98f3157245c0",
                "pdpHeartbeatIntervalMs":120000}`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

	err := PdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
PdpUpdateMessageHandler_Message_Unmarshal_Failure4
Description: Test by sending a invalid input message which should result in a Json unmarhsal error
Input: empty
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestPdpUpdateMessageHandler_Message_Unmarshal_Failure4(t *testing.T) {

	// invlaid params by mispelling a param  "source"

	messageString := `""`
	mockSender := new(mocks.PdpStatusSender)
	mockSender.On("SendPdpStatus", mock.Anything).Return(errors.New("Jsonunmarshal Error"))

	err := PdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
PdpUpdateMessageHandler_Fails_Sending_PdpUpdateResponse
Description: Test by sending a invalid attribute for pdpstate which should result in a failure in sending pdp update response
Input: invalid input config set for pdpstate
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestPdpUpdateMessageHandler_Fails_Sending_UpdateResponse(t *testing.T) {

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

	err := PdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}

/*
PdpUpdateMessageHandler_Invalid_Starttimeinterval
Description: Test by sending a invalid time value attribute for pdpstate which should result in a failure in starting heartbeat interval
Input: invalid input message for pdpstate heartbeat interval
Expected Output: Message Handler should exit gracefully stating the error.
*/
func TestPdpUpdateMessageHandler_Invalid_Starttimeinterval(t *testing.T) {

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

	err := PdpUpdateMessageHandler([]byte(messageString), mockSender)
	assert.Error(t, err)

}
