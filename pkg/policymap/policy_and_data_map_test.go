package policymap

import (
	// "encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"policy-opa-pdp/pkg/model"
)

func TestFormatPolicyAndDataMap(t *testing.T) {
	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test.policy.1", "policy-version": "1.0"},
	}

	result, err := formatPolicyAndDataMap(deployedPolicies)
	assert.NoError(t, err)
	assert.Contains(t, result, `"policy-id": "test.policy.1"`)
}

func TestFormatMapofAnyType(t *testing.T) {
	testMap := map[string]string{"key1": "value1"}
	result, err := FormatMapofAnyType(testMap)
	assert.NoError(t, err)
	assert.Contains(t, result, `"key1": "value1"`)
}

func TestFormatPolicyAndDataMap_EmptyMap(t *testing.T) {
	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test.policy.1", "data": make(chan int)},
	}

	_, err := formatPolicyAndDataMap(deployedPolicies)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to format json", "Expected JSONformatting error")
}

func TestUnmarshalLastDeployedPolicies_EmptyString(t *testing.T) {
	result, err := UnmarshalLastDeployedPolicies("")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(result))
}

func TestUnmarshalLastDeployedPolicies_ValidJSON(t *testing.T) {
	jsonData := `{"deployed_policies_dict": [{"data": ["role"],"policy": ["role"],"policy-id": "test.policy.1","policy-version": "1.0"}]}`
	result, err := UnmarshalLastDeployedPolicies(jsonData)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result))
	assert.Equal(t, "test.policy.1", result[0]["policy-id"])
}

func TestUpdateDeployedPoliciesinMap(t *testing.T) {
	LastDeployedPolicies = `{"deployed_policies_dict":[]}`

	policy := model.ToscaPolicy{
		Metadata: model.Metadata{
			PolicyID:      "new.policy",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data:   map[string]string{"key1": "value1"},
			Policy: map[string]string{"rule1": "allow"},
		},
	}

	result, err := UpdateDeployedPoliciesinMap(policy)
	assert.NoError(t, err)
	assert.Contains(t, result, `"policy-id": "new.policy"`)
}

func TestUpdateDeployedPoliciesinMap_Negative(t *testing.T) {
	LastDeployedPolicies = `{deployed_policies_dict:[]}`

	policy := model.ToscaPolicy{
		Metadata: model.Metadata{
			PolicyID:      "new.policy",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data:   map[string]string{"key1": "value1"},
			Policy: map[string]string{"rule1": "allow"},
		},
	}

	result, _ := UpdateDeployedPoliciesinMap(policy)
	assert.NotContains(t, result, "new.policy canot be added due to invalid json format")
}

func TestRemoveUndeployedPoliciesfromMap(t *testing.T) {
	LastDeployedPolicies = `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`

	undeploy := map[string]interface{}{
		"policy-id":      "test.policy.1",
		"policy-version": "1.0",
	}

	result, err := RemoveUndeployedPoliciesfromMap(undeploy)
	assert.NoError(t, err)
	assert.NotContains(t, result, `"policy-id": "test.policy.1"`)
}

func TestRemoveUndeployedPoliciesfromMap_Negative(t *testing.T) {
	LastDeployedPolicies = `{"deployed_policies_dict":[{"policy-id":"test.policy.1"policy-version":"1.0"}]}`

	undeploy := map[string]interface{}{
		"policy-id":      "test.policy.1",
		"policy-version": "1.0",
	}

	result, _ := RemoveUndeployedPoliciesfromMap(undeploy)
	assert.NotContains(t, result, `"policy-id": "test.policy.1"`)
}

func TestRemoveUndeployedPolicies_NonExistingPolicyfromMap(t *testing.T) {
	LastDeployedPolicies = `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`

	undeploy := map[string]interface{}{
		"policy-id":      "new.policy",
		"policy-version": "1.0",
	}

	result, err := RemoveUndeployedPoliciesfromMap(undeploy)
	assert.NoError(t, err)
	assert.Contains(t, result, `"policy-id": "test.policy.1"`)
	assert.NotContains(t, result, `"policy-id": "new.policy"`)
}

func TestVerifyAndReturnPoliciesToBeDeployed(t *testing.T) {
	lastDeployedPolicies := `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{Name: "new.policy", Version: "1.0"},
		},
	}

	result := VerifyAndReturnPoliciesToBeDeployed(lastDeployedPolicies, pdpUpdate)
	assert.Equal(t, 1, len(result))
	assert.Equal(t, "new.policy", result[0].Name)
}

func TestVerifyAndReturnPoliciesToBeDeployed_Negative(t *testing.T) {
	lastDeployedPolicies := `{"deployed_policies_dict":[{"policy-id":"test.policy.1""policy-version":"1.0"}]}`
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{Name: "new.policy", Version: "1.0"},
		},
	}

	result := VerifyAndReturnPoliciesToBeDeployed(lastDeployedPolicies, pdpUpdate)
	assert.NotEqual(t, "new.policy", result)
}

func TestVerifyAndReturnPoliciesToBeDeployedi_ExistingPolicy(t *testing.T) {
	lastDeployedPolicies := `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{Name: "test.policy.1", Version: "1.0"},
		},
	}

	result := VerifyAndReturnPoliciesToBeDeployed(lastDeployedPolicies, pdpUpdate)
	assert.Empty(t, result, "Expected result tobe empty as policy is already deployed")
}

func TestExtractDeployedPolicies(t *testing.T) {
	policiesMap := `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`

	result := ExtractDeployedPolicies(policiesMap)
	assert.Equal(t, 1, len(result))
	assert.Equal(t, "test.policy.1", result[0].Name)
}

func TestExtractDeployedPolicies_Negative(t *testing.T) {
	policiesMap := `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":1.0"}]}`

	result := ExtractDeployedPolicies(policiesMap)
	assert.Equal(t, 0, len(result))
	assert.NotEqual(t, "test.policy.1", result)
}

func TestExtractDeployedPolicies_MissingPolicyID(t *testing.T) {
	policiesMap := `{"deployed_policies_dict":[{"policy-id": 123,"policy-version":"1.0"}]}`

	result := ExtractDeployedPolicies(policiesMap)
	assert.Nil(t, result)
}

func TestCheckIfPolicyAlreadyExists(t *testing.T) {
	LastDeployedPolicies = `{"deployed_policies_dict":[{"policy-id":"existing.policy","policy-version":"1.0"}]}`

	exists := CheckIfPolicyAlreadyExists("existing.policy")
	assert.True(t, exists)

	notExists := CheckIfPolicyAlreadyExists("nonexistent.policy")
	assert.False(t, notExists)
}

func TestCheckIfPolicyAlreadyExists_JSONParsingFailure(t *testing.T) {
	LastDeployedPolicies = `{"deployed_policies_dict":[{"policy-id":"existing.policy,"policy-version":"1.0"}]}`

	exists := CheckIfPolicyAlreadyExists("existing.policy")
	assert.False(t, exists)
}

func TestGetTotalDeployedPoliciesCountFromMap(t *testing.T) {
	LastDeployedPolicies = `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`

	count := GetTotalDeployedPoliciesCountFromMap()
	assert.Equal(t, 1, count)
}

func TestGetTotalDeployedPoliciesCountFromMap_Negative(t *testing.T) {
	LastDeployedPolicies = `{"deployed_policies_dict":[{"policy-id":test.policy.1","policy-version":"1.0"}]}`

	count := GetTotalDeployedPoliciesCountFromMap()
	assert.Equal(t, 0, count)
}
