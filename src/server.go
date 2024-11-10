// sleeponlan
package main

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"time"
)

// ###################################
//	SERVER - RECEVING SHUTDOWN
// ###################################

func serverModeUDP(listenAddress string, confRemoteAddr string, rateLimiter <-chan time.Time, externalCheckScript string, testMessage string, filterMessage string, maxPayloadSize int, TOTPSecret []byte, AESGCMCipherBlock cipher.AEAD, command *exec.Cmd) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError("SOL Server panic while listening for UDP shutdown", fmt.Errorf("%v", r), true)
		}
	}()

	// Setup network info
	localAddress, err := net.ResolveUDPAddr("udp", listenAddress)
	logError("failed to resolve local UDP address", err, true)

	// Open local socket
	localSocket, err := net.ListenUDP("udp", localAddress)
	logError("failed to create local UDP socket", err, true)
	defer localSocket.Close()

	// Show progress to user
	logMessage(fmt.Sprintf("SleepOnLAN Server started, listening on UDP socket %s", listenAddress))

	// Wait for data in receive buffer and process
	recvBuffer := make([]byte, maxPayloadSize)
	for {
		// Wait for the next tick to limit the packet processing rate
		<-rateLimiter

		// Wait for incoming packet and write payload into buffer
		recvDataLen, remoteAddr, err := localSocket.ReadFrom(recvBuffer)
		if err != nil {
			logMessage(fmt.Sprintf("Failed: reading socket resulted in error: %v", err))
			continue
		}

		// Process received packet
		BreakLoop := ParsePayload(recvBuffer, recvDataLen, maxPayloadSize, remoteAddr.String(), confRemoteAddr, externalCheckScript, testMessage, filterMessage, TOTPSecret, AESGCMCipherBlock, command)

		// Exit server if requested (shutdown commencing)
		if BreakLoop {
			break
		}
	}
}

func serverModeTCP(listenAddress string, confRemoteAddr string, rateLimiter <-chan time.Time, externalCheckScript string, testMessage string, filterMessage string, maxPayloadSize int, TOTPSecret []byte, AESGCMCipherBlock cipher.AEAD, command *exec.Cmd) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError("SOL Server panic while listening for TCP shutdown", fmt.Errorf("%v", r), true)
		}
	}()

	// Start local listener
	listener, err := net.Listen("tcp", listenAddress)
	logError("failed to create local TCP listener", err, true)
	defer listener.Close()

	// Show progress to user
	logMessage(fmt.Sprintf("SleepOnLAN Server started, listening on TCP socket %s", listenAddress))

	// Wait for data in receive buffer and process
	recvBuffer := make([]byte, maxPayloadSize)
	for {
		// Wait for the next tick to limit the connection processing rate
		<-rateLimiter

		// Accept incoming connection
		tcpConn, err := listener.Accept()
		if err != nil {
			logMessage(fmt.Sprintf("Failed: error accepting TCP connection: %v", err))
			tcpConn.Close()
			continue
		}

		// Write payload into buffer
		recvDataLen, err := tcpConn.Read(recvBuffer)
		if err != nil {
			logMessage(fmt.Sprintf("Failed: reading packet payload resulted in error: %v", err))
			tcpConn.Close()
			continue
		}

		// Close connection
		tcpConn.Close()

		// Process received packet
		BreakLoop := ParsePayload(recvBuffer, recvDataLen, maxPayloadSize, tcpConn.RemoteAddr().String(), confRemoteAddr, externalCheckScript, testMessage, filterMessage, TOTPSecret, AESGCMCipherBlock, command)

		// Exit server if requested (shutdown commencing)
		if BreakLoop {
			break
		}
	}
}

func ParsePayload(recvBuffer []byte, recvDataLen int, maxPayloadSize int, remoteAddr string, confRemoteAddr string, externalCheckScript string, testMessage string, filterMessage string, TOTPSecret []byte, AESGCMCipherBlock cipher.AEAD, command *exec.Cmd) (BreakLoop bool) {
	// Don't process further if data length is over max payload size
	if recvDataLen > maxPayloadSize {
		return
	}

	// Read from buffer
	receivedCipherText := recvBuffer[:recvDataLen]

	// Check correct network endpoint
	if remoteAddr != confRemoteAddr {
		logMessage(fmt.Sprintf("Failed: received Invalid Shutdown Packet from %s. IP or Port incorrect.", remoteAddr))
		return
	}

	// Decrypt received message
	sessionIV := MutateIVwithTime(TOTPSecret)
	plainMessage, err := AESGCMCipherBlock.Open(nil, sessionIV, receivedCipherText, nil)
	if err != nil {
		logMessage(fmt.Sprintf("Failed: decryption of payload from %s resulted in error: %v", remoteAddr, err))
		return
	}

	// If message text is test, log and continue
	if string(plainMessage) == testMessage {
		_, err := exec.LookPath(filepath.Base(command.Path))
		if err != nil {
			logMessage("Failed: (test) Shutdown executable not found.")
			return
		}
		logMessage(fmt.Sprintf("Success: (test) Received Valid Shutdown Packet from %s. Shutdown executable found.", remoteAddr))
		return
	}

	// Check message validity against config string or validity against the hard coded test message
	if string(plainMessage) != filterMessage {
		logMessage(fmt.Sprintf("Failed: received Invalid Shutdown Packet from %s. Message Data is incorrect.", remoteAddr))
		return
	}

	// If precheck script was supplied, run and check
	if externalCheckScript != "" {
		// Format exec command
		precheckCommand := exec.Command(externalCheckScript)

		// Run external precheck script
		err = precheckCommand.Run()
		if err != nil {
			// Log error if not the expected exit status
			if err.Error() != "exit status 1" {
				logMessage(fmt.Sprintf("Failed: Pre-check script error: %v", err))
				return
			}
			// Abort shutdown if external script is an error exit (ideally, purposely code 1)
			logMessage("Failed: Aborting shutdown, precheck script shutdown conditions are not met.")
			return
		}
	}

	// Create a buffer to capture stderr
	var stderr bytes.Buffer
	command.Stderr = &stderr

	// Shutdown the system
	logMessage(fmt.Sprintf("Success: Received Valid Shutdown Packet from %s. Initiating system shutdown.", remoteAddr))
	err = command.Run()
	if err == nil {
		// Shutdown commencing, break processing loop and allow server to exit
		BreakLoop = true
		return
	}

	// If shutdown failed, return and continue processing packets
	logMessage(fmt.Sprintf("Failed: shutdown command resulted in error: %s", stderr.String()))
	return
}

