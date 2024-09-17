package main

import "math"

type HandleList[T interface{}] map[int32]T

// insert a value and return the positive handle, or errDeviceLimitHit if full
func insertHandle[T interface{}](hl map[int32]T, value T) int32 {
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := hl[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		return errDeviceLimitHit
	}
	hl[i] = value
	return i
}
