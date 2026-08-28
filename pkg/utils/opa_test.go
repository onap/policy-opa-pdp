// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2026: Deutsche Telekom
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

package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"policy-opa-pdp/consts"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validRego = `package role

import rego.v1

default allow := false

allow if data.node.role.user_roles[input.user]
`

// stagePolicyAndData points consts.Policies/consts.Data at temp directories laid out the way
// the deploy handler lays them out, and returns them for the caller to populate further.
func stagePolicyAndData(t *testing.T) (policyDir string, dataDir string) {
	t.Helper()

	root := t.TempDir()
	policyDir = filepath.Join(root, "policies", "role")
	dataDir = filepath.Join(root, "data", "node", "role")
	require.NoError(t, os.MkdirAll(policyDir, 0750))
	require.NoError(t, os.MkdirAll(dataDir, 0750))

	originalPolicies, originalData := consts.Policies, consts.Data
	consts.Policies = filepath.Join(root, "policies")
	consts.Data = filepath.Join(root, "data")
	t.Cleanup(func() {
		consts.Policies = originalPolicies
		consts.Data = originalData
	})

	return policyDir, dataDir
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0600))
}

func TestBuildBundle(t *testing.T) {
	policyDir, dataDir := stagePolicyAndData(t)
	writeFile(t, policyDir, "policy.rego", validRego)
	writeFile(t, dataDir, "data.json", `{"user_roles": {"alice": ["admin"]}}`)

	assert.NoError(t, BuildBundle())
}

func TestBuildBundle_ParseError(t *testing.T) {
	policyDir, _ := stagePolicyAndData(t)
	writeFile(t, policyDir, "policy.rego", "package role\n\nallow if {\n")

	err := BuildBundle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rego_parse_error")
}

// A module can parse cleanly and still be rejected by the compiler. This asserts BuildBundle
// really compiles rather than only parsing, which is the whole point of the deploy-time check.
func TestBuildBundle_CompileError(t *testing.T) {
	policyDir, _ := stagePolicyAndData(t)
	writeFile(t, policyDir, "policy.rego", "package role\n\nallow if undefined_local\n")

	err := BuildBundle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rego_unsafe_var_error")
}

func TestBuildBundle_InvalidData(t *testing.T) {
	policyDir, dataDir := stagePolicyAndData(t)
	writeFile(t, policyDir, "policy.rego", validRego)
	writeFile(t, dataDir, "data.json", "{not json")

	assert.Error(t, BuildBundle())
}

func TestParseAST(t *testing.T) {
	astJSON, err := ParseAST(validRego)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(astJSON, &parsed))
	assert.Contains(t, parsed, "package")
	assert.Contains(t, parsed, "rules")
}

func TestParseAST_ParseError(t *testing.T) {
	astJSON, err := ParseAST("this is not rego")
	assert.Nil(t, astJSON)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse policy")
	// The synthetic module name stands in for the temp file the CLI used to need.
	assert.Contains(t, err.Error(), consts.StandardPolicyName)
}

// Rego v0 bodies without `if` are rejected: the parser runs in v1 mode, matching the
// V1Compatible OPA SDK instance that will evaluate the policy.
func TestParseAST_RejectsRegoV0Syntax(t *testing.T) {
	_, err := ParseAST("package role\n\nallow { true }\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "`if` keyword is required before rule body")
}
