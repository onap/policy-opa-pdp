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
