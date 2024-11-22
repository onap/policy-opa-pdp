package metrics

import "sync"

//global counter variables
var IndeterminantDecisionsCount int64
var PermitDecisionsCount int64
var DenyDecisionsCount int64
var TotalErrorCount int64
var mu sync.Mutex

// Increment counter
func IncrementIndeterminantDecisionsCount() {
	mu.Lock()
	IndeterminantDecisionsCount++
	mu.Unlock()
}

// returns pointer to the counter
func IndeterminantDecisionsCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &IndeterminantDecisionsCount
}

// Increment counter
func IncrementPermitDecisionsCount() {
	mu.Lock()
	PermitDecisionsCount++
	mu.Unlock()
}

// returns pointer to the counter
func PermitDecisionsCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &PermitDecisionsCount
}

// Increment counter
func IncrementDenyDecisionsCount() {
	mu.Lock()
	DenyDecisionsCount++
	mu.Unlock()
}

// returns pointer to the counter
func DenyDecisionsCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &DenyDecisionsCount
}

// Increment counter
func IncrementTotalErrorCount() {
	mu.Lock()
	TotalErrorCount++
	mu.Unlock()
}

// returns pointer to the counter
func TotalErrorCountRef() *int64 {
	mu.Lock()
	defer mu.Unlock()
	return &TotalErrorCount
}
