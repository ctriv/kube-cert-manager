package util

import (
	"sort"
	"strings"
)

func NormalizedAltNames(names []string) []string {
	arr := make([]string, len(names))
	copy(arr, names)
	for i := range arr {
		arr[i] = strings.ToLower(names[i])
	}
	sort.Strings(arr)

	return arr
}
