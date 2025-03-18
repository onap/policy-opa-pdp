package utils

import (
    "strings"
)

// Custom type for sorting
type ByDotCount struct {
    Keys   []string
    Ascend bool
}

// Implement sort.Interface for ByDotCount
func (a ByDotCount) Len() int           { return len(a.Keys) }

func (a ByDotCount) Swap(i, j int)      { a.Keys[i], a.Keys[j] = a.Keys[j], a.Keys[i] }

func (a ByDotCount) Less(i, j int) bool {
    if a.Ascend {
        return strings.Count(a.Keys[i], ".") < strings.Count(a.Keys[j], ".")
    }
    return strings.Count(a.Keys[i], ".") > strings.Count(a.Keys[j], ".")
}