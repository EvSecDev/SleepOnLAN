// sleeponlan
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// ###################################
//      CRYPTO
// ###################################

// This adds a time factor to mutate an IV that normally provides altered cipher text per encrypted payload - with a shared secret, this creates time-based authentication
func MutateIVwithTime(totpSecret []byte) []byte {
	// Get current time
	currentUTCTime := time.Now().UTC()

	// Get the current second
	currentSecond := currentUTCTime.Second()

	// Determine the 15sec block that the current second is in
	secondBlockTime := (currentSecond / 15) * 15

	// 64bit slice for current time in block form
	currentBlockTime := make([]byte, 8)

	// Create full time block which current time is in
	binary.BigEndian.PutUint64(currentBlockTime, uint64(currentUTCTime.Unix()-int64(currentSecond)+int64(secondBlockTime)))

	// Add current time block to the shared secret
	TimeBlockAndSecret := append(currentBlockTime, totpSecret...)

	// Hash combination of current time block and shared secret
	TOTP := sha256.Sum256(TimeBlockAndSecret)

	// Return truncated hash for use as the current sessions encryption IV
	return TOTP[:12]
}

// Network latency compensator - allow for small drift between client and server before totp is invalid
func WaitForTimeWindow() {
	for {
		// Current second for this loop
		currentUTCTime := time.Now().UTC()
		currentSecond := currentUTCTime.Second()

		// Break loops when within bounds
		if (currentSecond >= 1 && currentSecond <= 14) ||
			(currentSecond >= 16 && currentSecond <= 29) ||
			(currentSecond >= 31 && currentSecond <= 44) ||
			(currentSecond >= 46 && currentSecond <= 59) {
			break
		}

		// Sleep for a short duration to avoid busy waiting
		time.Sleep(50 * time.Millisecond)
	}
}

