// sleeponlan
package main

import (
	"crypto/cipher"
	"fmt"
	"net"
)

// ###################################
//	CLIENT - SENDING SHUTDOWN
// ###################################

// Handles both TCP and UDP based on useTCP boolean
// Encrypts filterMessage with TOTPSecret, then sends to the remote addess
func clientConnect(filterMessage string, TOTPSecret []byte, AESGCMCipherBlock cipher.AEAD, listenAddress string, remoteAddress string, useTCP bool) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError(fmt.Sprintf("SOL client panic while sending shutdown to %s", remoteAddress), fmt.Errorf("%v", r), false)
		}
	}()

	// Resolve remote addr and local addr
	var listenAddr net.Addr
	var remoteAddr net.Addr
	var L4Protocol string
	var err error
	if useTCP {
		L4Protocol = "tcp"
		listenAddr, err = net.ResolveTCPAddr(L4Protocol, listenAddress)
		remoteAddr, err = net.ResolveTCPAddr(L4Protocol, remoteAddress)
	} else {
		L4Protocol = "udp"
		listenAddr, err = net.ResolveUDPAddr(L4Protocol, listenAddress)
		remoteAddr, err = net.ResolveUDPAddr(L4Protocol, remoteAddress)
	}
	logError("failed to resolve addresses", err, true)

	// Create a Dialer with the local address
	dialer := net.Dialer{
		LocalAddr: listenAddr,
	}

	// Open socket to remote
	socket, err := dialer.Dial(L4Protocol, remoteAddr.String())
	logError("failed to open local socket", err, true)
	defer socket.Close()

	// Encrypt the message with time-based IV
	WaitForTimeWindow()
	sessionIV := MutateIVwithTime(TOTPSecret)
	CipherText := AESGCMCipherBlock.Seal(nil, sessionIV, []byte(filterMessage), nil)

	// Ensure CipherText is not too large - multiple packets/fragmentation is not supported in this program
	if len(CipherText) > maxPayloadSize {
		logError("failed to send message", fmt.Errorf("unable to send payload larger than %d bytes (payload is currently %d bytes)", maxPayloadSize, len(CipherText)), true)
	}

	// Send the message to the remote host
	_, err = socket.Write(CipherText)
	logError("failed to send message", err, true)

	// Notify
	logMessage(fmt.Sprintf("Sent Shutdown Packet to %s", remoteAddress))
}
