package metrics

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCounters(t *testing.T) {
	var wg sync.WaitGroup

	// Test IncrementIndeterminantDecisionsCount and IndeterminantDecisionsCountRef
	IndeterminantDecisionsCount = 0
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			IncrementIndeterminantDecisionsCount()
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(10), *IndeterminantDecisionsCountRef())

	// Test IncrementPermitDecisionsCount and PermitDecisionsCountRef
	PermitDecisionsCount = 0
	wg.Add(15)
	for i := 0; i < 15; i++ {
		go func() {
			defer wg.Done()
			IncrementPermitDecisionsCount()
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(15), *PermitDecisionsCountRef())

	// Test IncrementDenyDecisionsCount and DenyDecisionsCountRef
	DenyDecisionsCount = 0
	wg.Add(20)
	for i := 0; i < 20; i++ {
		go func() {
			defer wg.Done()
			IncrementDenyDecisionsCount()
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(20), *DenyDecisionsCountRef())

	// Test IncrementTotalErrorCount and TotalErrorCountRef
	TotalErrorCount = 0
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			IncrementTotalErrorCount()
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(5), *TotalErrorCountRef())
}
