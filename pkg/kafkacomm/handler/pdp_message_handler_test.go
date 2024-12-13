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
//

package handler

import (
	"github.com/stretchr/testify/assert"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/pdpattributes"
	"testing"
	//		"context"
	//	       "encoding/json"
	//		"errors"
	//		"policy-opa-pdp/pkg/kafkacomm/mocks"
)

/*
checkIfMessageIsForOpaPdp_Check
Description: Validating Message Attributes
Input: PDP message
Expected Output: Returning true stating all the values are validated successfully
*/
func TestCheckIfMessageIsForOpaPdp_Check(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = "opa-3a318049-813f-4172-b4d3-7d4f466e5b80"
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "opa"

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Its a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_Message_Name
Description: Validating Message Attributes
Input: PDP message with name as empty
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_Message_Name(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "opa"

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Not a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_PdpGroup
Description: Validating Message Attributes
Input: PDP message with invalid PdpGroup
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_PdpGroup(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "opa"

	pdpattributes.PdpSubgroup = "opa"
	assert.True(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Its a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_EmptyPdpGroup
Description: Validating Message Attributes
Input: PDP Group Empty
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_EmptyPdpGroup(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = ""
	opapdpMessage.PdpSubgroup = "opa"

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Not a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_PdpSubgroup
Description: Validating Message Attributes
Input: PDP message with invalid PdpSubgroup
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_PdpSubgroup(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "opa"

	pdpattributes.PdpSubgroup = "opa"
	assert.True(t, checkIfMessageIsForOpaPdp(opapdpMessage), "It's a valid Opa Pdp Message")

}

/*
checkIfMessageIsForOpaPdp_Check_IncorrectPdpSubgroup
Description: Validating Message Attributes
Input: PDP message with empty  PdpSubgroup
Expected Output: Returning Error since it is not valid message
*/
func TestCheckIfMessageIsForOpaPdp_Check_IncorrectPdpSubgroup(t *testing.T) {

	var opapdpMessage OpaPdpMessage

	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = "o"

	pdpattributes.PdpSubgroup = "opa"
	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Not a valid Opa Pdp Message")

}

func TestCheckIfMessageIsForOpaPdp_EmptyPdpSubgroupAndGroup(t *testing.T) {
	var opapdpMessage OpaPdpMessage
	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = ""
	opapdpMessage.PdpSubgroup = ""

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Message should be invalid when PdpGroup and PdpSubgroup are empty")
}

func TestCheckIfMessageIsForOpaPdp_ValidBroadcastMessage(t *testing.T) {
	var opapdpMessage OpaPdpMessage
	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_UPDATE"
	opapdpMessage.PdpGroup = "opaGroup"
	opapdpMessage.PdpSubgroup = ""

	pdpattributes.PdpSubgroup = "opa"
	consts.PdpGroup = "opaGroup"

	assert.True(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Valid broadcast message should pass the check")
}

func TestCheckIfMessageIsForOpaPdp_InvalidGroupMismatch(t *testing.T) {
	var opapdpMessage OpaPdpMessage
	opapdpMessage.Name = ""
	opapdpMessage.MessageType = "PDP_STATUS"
	opapdpMessage.PdpGroup = "wrongGroup"
	opapdpMessage.PdpSubgroup = ""

	consts.PdpGroup = "opaGroup"

	assert.False(t, checkIfMessageIsForOpaPdp(opapdpMessage), "Message with mismatched PdpGroup should fail")
}

// Test SetShutdownFlag and IsShutdown
func TestSetAndCheckShutdownFlag(t *testing.T) {
	assert.False(t, IsShutdown(), "Shutdown flag should be false initially")

	SetShutdownFlag()
	assert.True(t, IsShutdown(), "Shutdown flag should be true after calling SetShutdownFlag")
}
