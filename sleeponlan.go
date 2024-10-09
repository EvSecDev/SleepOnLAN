// sol-client
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ###################################
//      GLOBAL VARIABLES
// ###################################

type JsonConfig struct {
	ListenIP      string		`json:"listenIP"`
	ListenPort    string		`json:"listenPort"`
	Remote	      []RemoteHosts	`json:"remote"`
	EncryptionKey string      	`json:"encryptionKey"`
	TOTPSecret    string      	`json:"TOTPSecret"`
	FilterMessage string     	`json:"filterMessage"`
	RemoteLog     RemoteLog  	`json:"remoteLog"`
	FileLog       FileLog    	`json:"fileLog"`
}

type RemoteHosts struct {
	IP      string    `json:"IP"`
	Port    string    `json:"Port"`
}

type RemoteLog struct {
	Enabled    bool   `json:"enabled"`
	SyslogIP   string `json:"syslogDestinationIP"`
	SyslogPort string `json:"syslogDestinationPort"`
}

type FileLog struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"logPath"`
}

// For syslog messages
var remoteLogEnabled bool
var syslogAddress *net.UDPAddr

// For file logging
var fileLogEnabled bool
var logFilePath string

// ###################################
//      EXCEPTION HANDLING
// ###################################

func logError(errorDescription string, errorMessage error, exitRequested bool) {
	// Return early if no error
	if errorMessage == nil {
		return
	}

	// Create formatted error message and give to message func
	fullMessage := "Error: " + errorDescription + ": " + errorMessage.Error()
	logMessage(fullMessage)

	// Exit prog after sending error messages
	if exitRequested {
		os.Exit(1)
	}
}

func logMessage(initmessage string) {
	var err error
	message := initmessage + "\n"

	// Write to file
	if fileLogEnabled {
		err = logToFile(message)
		if err == nil {
			return
		}
	}

	// Write to remote socket
	if remoteLogEnabled {
		err = logToRemote(message)
		if err == nil {
			return
		}
	}

	// Prep err from functions for writing to stdout
	if err != nil && err.Error() != "syslogAddress is empty" {
		message = "Failed to send message to desired location: " + err.Error() + " - ORIGINAL MESSAGE: " + message
	}

	// Write to stdout if other messages aren't selected or fail
	fmt.Printf("%s", message)
}

func logToFile(message string) error {
	// Add formatting to log line
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMsg := timestamp + " sleeponlan: " + message

	// Open file and append
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	// Write log to file
	_, err = logFile.Write([]byte(logMsg))
	if err != nil {
		return err
	}
	return nil
}

func logToRemote(message string) error {
	// If no address, go to stdout write
	if syslogAddress == nil {
		return fmt.Errorf("syslogAddress is empty")
	}

	// Open socket to remote syslog server
	conn, err := net.DialUDP("udp", nil, syslogAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Format message
	syslogMsg := fmt.Sprintf("<%d>%s: %s", syslog.LOG_INFO, "sleeponlan", message)

	// Write message to remote host - failure writes to stdout
	_, err = conn.Write([]byte(syslogMsg))
	if err != nil {
		return err
	}

	return nil
}

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

// ###################################
//	START HERE
// ###################################

func main() {
	var configFile string
	var externalCheckScript string
	versionFlagExists := flag.Bool("V", false, "Print Version Information")
	flag.StringVar(&configFile, "c", "solconfig.json", "Path to the configuration file")
	serverFlagExists := flag.Bool("server", false, "Start the server (receiving shutdown)")
	clientFlagExists := flag.Bool("client", false, "Run the client (sending shutdown)")
	sendTest := flag.Bool("send-test", false, "Send test shutdown packet (requires --client)")
	useTCP := flag.Bool("tcp", false, "Use TCP communication for client/server network connections (Does not apply to remote log addresses)")
	flag.StringVar(&externalCheckScript, "precheck-script", "", "Run external script prior to shutdown. If script exits with code 1, shutdown will be aborted. (requires --server)")
	flag.Parse()

	// Meta info print out
	if *versionFlagExists {
		fmt.Printf("SleepOnLAN v1.1.0 compiled using GO(%s) v1.23.1 on %s architecture %s\n", runtime.Compiler, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("First party packages:\n")
		fmt.Printf("bytes crypto/aes crypto/cipher encoding/binary encoding/hex encoding/json crypto/sha256 runtime flag fmt log/syslog net os os/exec strings time\n")
		os.Exit(0)
	}

	var err error

	// Grab configuration options from file
	jsonConfig, err := os.ReadFile(configFile)
	logError("failed to read config file", err, true)

	// Parse json from config file
	var config JsonConfig
	err = json.Unmarshal(jsonConfig, &config)
	logError("failed to parse JSON config", err, true)

	// Setup File Logging
	if config.FileLog.Enabled {
		logFilePath = config.FileLog.Path
		fileLogEnabled = true
	} else {
		fileLogEnabled = false
	}

	// Setup Remote Logging
	if config.RemoteLog.Enabled {
		// Set global for syslog address
		syslogRemoteAddr := PairIPPort(config.RemoteLog.SyslogIP, config.RemoteLog.SyslogPort)
		syslogAddress, err = net.ResolveUDPAddr("udp", syslogRemoteAddr)
		logError("failed to resolve syslog address", err, true)

		// Set global for message handling awareness
		remoteLogEnabled = true
	} else {
		remoteLogEnabled = false
	}

	// Validate key and secret from config
	if len(config.EncryptionKey) != 32 {
		logError("invalid key size", fmt.Errorf("the key must be 32 bytes (256-bit), but the key is %d bytes", len(config.EncryptionKey)), true)
	}
	if len(config.TOTPSecret) != 24 {
		logError("invalid totp secret size", fmt.Errorf("the secret should be 24 bytes (192-bit), but it is %d bytes", len(config.TOTPSecret)), true)
	}

	// Format key and IV
	encryptionKey, err := hex.DecodeString(config.EncryptionKey)
	logError("failed to decode supplied key", err, true)

	TOTPSecret, err := hex.DecodeString(config.TOTPSecret)
	logError("failed to decode supplied encryption IV", err, true)

	// Setup encrypted message
	CipherBlock, err := aes.NewCipher(encryptionKey)
	logError("failed to create cipher block", err, true)

	AESGCMCipherBlock, err := cipher.NewGCM(CipherBlock)
	logError("failed to create AES-GCM cipher", err, true)

	// Setup Network info
	listenAddress := PairIPPort(config.ListenIP, config.ListenPort)

	// Prep message text
	testMessage := "deadbeefdeadbeefdeadbeefdeadbeef1928374655647382910"

	// If test is requested (and in client mode), override message with test string
	if *sendTest && *clientFlagExists {
		config.FilterMessage = testMessage
	}

	// Unified value for client, server udp and tcp payload sizes
	maxPayloadSize := 1300

	// Run client if requested
	if *clientFlagExists {
		// Loop over endpoints in config and send packet
		for arrayPosition, _ := range config.Remote {
			// Setup remote address
			remoteAddress := PairIPPort(config.Remote[arrayPosition].IP, config.Remote[arrayPosition].Port)

			// Send packet
			clientConnect(config.FilterMessage, TOTPSecret, AESGCMCipherBlock, listenAddress, remoteAddress, maxPayloadSize, *useTCP)
		}
		os.Exit(0)
	}

	// Start server if requested
	if *serverFlagExists {
		// Prepare correct shutdown command
		var command *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			command = exec.Command("shutdown", "/s", "/t", "0")
		case "linux", "darwin":
			command = exec.Command("poweroff", "-p")
		case "freebsd":
			command = exec.Command("shutdown", "-p", "now")
		default:
			logError("unable to determine OS type", fmt.Errorf("will not know which shutdown command to use, refusing to continue"), true)
		}

		// Check if external precheck script exists before starting server
		if externalCheckScript != "" {
			_, err := os.Stat(externalCheckScript)
			if os.IsNotExist(err) {
				logError("problem loading precheck script", err, true)
			}
		}

		// Join exepcted IP and port for compare on connect
		confRemoteAddr := PairIPPort(config.Remote[0].IP, config.Remote[0].Port)

		// Packet processing rate limit - 1 second / 5 packets (200ms in between packets)
		rateLimiter := time.Tick(200 * time.Millisecond)

		// Start the server
		if *useTCP {
			serverModeTCP(listenAddress, confRemoteAddr, rateLimiter, externalCheckScript, testMessage, config.FilterMessage, maxPayloadSize, TOTPSecret, AESGCMCipherBlock, command)
		} else {
			serverModeUDP(listenAddress, confRemoteAddr, rateLimiter, externalCheckScript, testMessage, config.FilterMessage, maxPayloadSize, TOTPSecret, AESGCMCipherBlock, command)
		}
		os.Exit(0)
	}

	// If no arguments
	fmt.Printf("No arguments specified! Use '-h' or '--help' to guide your way.\n")
	os.Exit(0)
}

// ###################################
//	CLIENT - SENDING SHUTDOWN
// ###################################

func clientConnect(filterMessage string, TOTPSecret []byte, AESGCMCipherBlock cipher.AEAD, listenAddress string, remoteAddress string, maxPayloadSize int, useTCP bool) {
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
	logError("failed to resolve addresses", err ,true)

	// Create a Dialer with the local address
	dialer := net.Dialer {
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

func ParsePayload(recvBuffer []byte, recvDataLen int, maxPayloadSize int, remoteAddr string, confRemoteAddr string, externalCheckScript string, testMessage string, filterMessage string, TOTPSecret []byte, AESGCMCipherBlock cipher.AEAD, command *exec.Cmd) bool {
	// Don't process further if data length is over max payload size
	if recvDataLen > maxPayloadSize {
		return false
	}

	// Read from buffer
	receivedCipherText := recvBuffer[:recvDataLen]

	// Check correct network endpoint
	if remoteAddr != confRemoteAddr {
		logMessage(fmt.Sprintf("Failed: received Invalid Shutdown Packet from %s. IP or Port incorrect.", remoteAddr))
		return false
	}

	// Decrypt received message
	sessionIV := MutateIVwithTime(TOTPSecret)
	plainMessage, err := AESGCMCipherBlock.Open(nil, sessionIV, receivedCipherText, nil)
	if err != nil {
		logMessage(fmt.Sprintf("Failed: decryption of payload from %s resulted in error: %v", remoteAddr, err))
		return false
	}

	// If message text is test, log and continue
	if string(plainMessage) == testMessage {
		_, err := exec.LookPath(filepath.Base(command.Path))
		if err != nil {
			logMessage("Failed: (test) Shutdown executable not found.")
			return false
		}
		logMessage(fmt.Sprintf("Success: (test) Received Valid Shutdown Packet from %s. Shutdown executable found.", remoteAddr))
		return false
	}

	// Check message validity against config string or validity against the hard coded test message
	if string(plainMessage) != filterMessage {
		logMessage(fmt.Sprintf("Failed: received Invalid Shutdown Packet from %s. Message Data is incorrect.", remoteAddr))
		return false
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
				return false
			}
			// Abort shutdown if external script is an error exit (ideally, purposely code 1)
			logMessage("Failed: Aborting shutdown, precheck script shutdown conditions are not met.")
			return false
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
		return true
	}

	// If shutdown failed, return and continue processing packets
	logMessage(fmt.Sprintf("Failed: shutdown command resulted in error: %s", stderr.String()))
	return false
}

// ###################################
//	MISC PARSING
// ###################################

func PairIPPort(IP string, Port string) string {
	var IPPort string
	if strings.Contains(IP, ":") {
		IPPort = "[" + IP + "]:" + Port
	} else {
		IPPort = IP + ":" + Port
	}
	return IPPort
}


