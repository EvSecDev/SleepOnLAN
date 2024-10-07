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
	"strconv"
	"strings"
	"time"
)

// ###################################
//      GLOBAL VARIABLES
// ###################################

type JsonConfig struct {
	ListenIP      string    `json:"listenIP"`
	ListenPort    string    `json:"listenPort"`
	RemoteIP      string    `json:"remoteIP"`
	RemotePort    string    `json:"remotePort"`
	Key           string    `json:"authKey"`
	IV            string    `json:"authIV"`
	FilterMessage string    `json:"filterMessage"`
	RemoteLog     RemoteLog `json:"remoteLog"`
	FileLog       FileLog   `json:"fileLog"`
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

type JsonMultiHost struct {
	RemoteIP   string `json:"remoteIP"`
	RemotePort string `json:"remotePort"`
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

func logMessage(message string) {
	var err error

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
	fmt.Printf("%s\n", message)
}

func logToFile(message string) error {
	// Open file and append
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	// Write log to file
	_, err = logFile.Write([]byte(message))
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

// This adds a time factor to the mutation that an IV normally provides to an encrypted payload - with a shared IV, this creates time-based authentication
func MutateIVwithTime(totpKey []byte) []byte {
	// Using current time in UTC
	currentUTCTime := time.Now().UTC()

	// Getting current second
	currentSecond := currentUTCTime.Second()

	// Getting the block
	blockTime := (currentSecond / 15) * 15

	// Slice for current time in block form
	totpCounter := make([]byte, 8)

	// Determine which block current time is in
	binary.BigEndian.PutUint64(totpCounter, uint64(currentUTCTime.Unix()-int64(currentSecond)+int64(blockTime)))

	// Hash combination of current time block and original IV
	CounterAndKey := append(totpCounter, totpKey...)
	TOTP := sha256.Sum256(CounterAndKey)

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
//
//	START HERE
//
// ###################################
func main() {
	var configFile string
	var multiHostsFile string
	var externalCheckScript string
	versionFlagExists := flag.Bool("V", false, "Print Version Information")
	flag.StringVar(&configFile, "c", "solconfig.json", "Path to the configuration file")
	serverFlagExists := flag.Bool("server", false, "Start the server (receiving shutdown)")
	clientFlagExists := flag.Bool("client", false, "Run the client (sending shutdown)")
	flag.StringVar(&multiHostsFile, "multihost-file", "", "Override single host with array of hosts in file (requires --client)")
	sendTest := flag.Bool("send-test", false, "Send test shutdown packet (requires --client)")
	flag.StringVar(&externalCheckScript, "precheck-script", "", "Run external script prior to shutdown. If script exits with code 1, shutdown will be aborted. (requires --server)")
	flag.Parse()

	// Meta info print out
	if *versionFlagExists {
		fmt.Printf("SleepOnLAN v1.0.2 compiled using GO(%s) v1.23.1 on %s architecture %s\n", runtime.Compiler, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("First party packages:\n")
		fmt.Printf("bytes crypto/aes crypto/cipher encoding/binary encoding/hex encoding/json crypto/sha256 runtime flag fmt log/syslog net os os/exec strings strconv time\n")
		os.Exit(0)
	}

	var err error

	// Set test message text
	TestOnlyFilterMessage := "deadbeefdeadbeefdeadbeefdeadbeef1928374655647382910"

	// Grab configuration options from file
	jsonConfig, err := os.ReadFile(configFile)
	logError("failed to read config file", err, true)

	// Parse json from config file
	var config JsonConfig
	err = json.Unmarshal(jsonConfig, &config)
	logError("failed to parse JSON config", err, true)

	// If test is requested (and in client mode), override message with test string
	if *sendTest && *clientFlagExists {
		config.FilterMessage = TestOnlyFilterMessage
	}

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
		if strings.Contains(config.RemoteLog.SyslogIP, ":") {
			syslogAddress, err = net.ResolveUDPAddr("udp", "["+config.RemoteLog.SyslogIP+"]:"+config.RemoteLog.SyslogPort)
		} else {
			syslogAddress, err = net.ResolveUDPAddr("udp", config.RemoteLog.SyslogIP+":"+config.RemoteLog.SyslogPort)
		}
		logError("failed to resolve syslog address", err, true)

		// Set global for message handling awareness
		remoteLogEnabled = true
	} else {
		remoteLogEnabled = false
	}

	// Validate key and IV from config
	if len(config.Key) != 32 {
		logError("invalid key size", fmt.Errorf("the key must be 32 bytes (256-bit), but the key is %d bytes", len(config.Key)), true)
	}
	if len(config.IV) != 24 {
		logError("invalid IV size", fmt.Errorf("the iv must be 24 bytes (192-bit), but the IV is %d bytes", len(config.IV)), true)
	}

	// Format key and IV
	encryptionKey, err := hex.DecodeString(config.Key)
	logError("failed to decode supplied key", err, true)

	encryptionIV, err := hex.DecodeString(config.IV)
	logError("failed to decode supplied encryption IV", err, true)

	// Setup encrypted message
	CipherBlock, err := aes.NewCipher(encryptionKey)
	logError("failed to create cipher block", err, true)

	AESGCMCipherBlock, err := cipher.NewGCM(CipherBlock)
	logError("failed to create AES-GCM cipher", err, true)

	// Setup Network info
	var listenAddress *net.UDPAddr
	if strings.Contains(config.ListenIP, ":") {
		listenAddress, err = net.ResolveUDPAddr("udp", "["+config.ListenIP+"]:"+config.ListenPort)
	} else {
		listenAddress, err = net.ResolveUDPAddr("udp", config.ListenIP+":"+config.ListenPort)
	}
	logError("failed to compile address IP and Port pair", err, true)

	// Open local UDP socket
	udpLocalSocket, err := net.ListenUDP("udp", listenAddress)
	logError("failed to create UDP socket", err, true)
	defer udpLocalSocket.Close()

	// Run client if requested
	if *clientFlagExists {
		byteMessage := []byte(config.FilterMessage)

		// If multihost file exists, load and parse, otherwise add single host from main config
		var remoteHosts []JsonMultiHost
		if multiHostsFile != "" {
			// Grab host overrides from file
			jsonMultiHostFile, err := os.ReadFile(multiHostsFile)
			logError("failed to read multihosts file", err, true)

			// Parse json from multihost file
			err = json.Unmarshal([]byte(jsonMultiHostFile), &remoteHosts)
			logError("failed to parse JSON multihost", err, true)
		} else {
			// Write single host to array
			remoteHosts = append(remoteHosts, JsonMultiHost{})
			remoteHosts[0] = JsonMultiHost{RemoteIP: config.RemoteIP, RemotePort: config.RemotePort}
		}

		for _, remoteHost := range remoteHosts {
			// Setup remote address
			var destinationAddress string
			if strings.Contains(remoteHost.RemoteIP, ":") {
				destinationAddress = "[" + remoteHost.RemoteIP + "]:" + remoteHost.RemotePort
			} else {
				destinationAddress = remoteHost.RemoteIP + ":" + remoteHost.RemotePort
			}

			// Run connection
			clientConnect(destinationAddress, TestOnlyFilterMessage, byteMessage, encryptionIV, AESGCMCipherBlock, udpLocalSocket)
		}

		// Close and exit
		udpLocalSocket.Close()
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

		// Show progress to user
		logMessage(fmt.Sprintf("SleepOnLAN Server started, listening on UDP socket %s\n", listenAddress))

		// Start the server
		serverMode(config, externalCheckScript, TestOnlyFilterMessage, encryptionIV, AESGCMCipherBlock, command, udpLocalSocket)

		// Close and exit
		udpLocalSocket.Close()
		os.Exit(0)
	}

	// If no arguments
	fmt.Printf("No arguments specified! Use '-h' or '--help' to guide your way.\n")
	os.Exit(0)
}

// ###################################
//
//	CLIENT - SENDING SHUTDOWN
//
// ###################################
func clientConnect(destinationAddress string, TestOnlyFilterMessage string, byteMessage []byte, encryptionIV []byte, AESGCMCipherBlock cipher.AEAD, udpLocalSocket *net.UDPConn) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError(fmt.Sprintf("SOL client panic while sending shutdown to %s", destinationAddress), fmt.Errorf("%v", r), false)
		}
	}()

	// Setup socket to send to remote host
	udpRemoteSocket, err := net.ResolveUDPAddr("udp", destinationAddress)
	logError("failed to resolve destination address", err, true)

	// Encrypt the message with time-based IV
	WaitForTimeWindow()
	sessionIV := MutateIVwithTime(encryptionIV)
	CipherText := AESGCMCipherBlock.Seal(nil, sessionIV, byteMessage, nil)

	// Ensure CipherText is not larger than max MTU (for the UDP payload) - multiple packets/fragmentation is not supported here
	if len(CipherText) > 1458 {
		logError("failed to send message", fmt.Errorf("unable to send udp payload larger than 1458 bytes (current payload is %d bytes)", len(CipherText)), true)
	}

	// Send the message to the remote host
	_, err = udpLocalSocket.WriteTo(CipherText, udpRemoteSocket)
	logError("failed to send message", err, true)

	// Notify
	logMessage(fmt.Sprintf("Sent Shutdown Packet to %s", destinationAddress))
}

// ###################################
//
//	SERVER - RECEVING SHUTDOWN
//
// ###################################
func serverMode(config JsonConfig, externalCheckScript string, TestOnlyFilterMessage string, encryptionIV []byte, AESGCMCipherBlock cipher.AEAD, command *exec.Cmd, udpLocalSocket *net.UDPConn) {
	// Recover from panic
	defer func() {
		if r := recover(); r != nil {
			logError("SOL Server panic while listening for shutdown", fmt.Errorf("%v", r), true)
		}
	}()

	// Packet processing rate limit - 1 second / 5 packets
	packetRateLimit := time.Second / time.Duration(5)
	rateLimiter := time.Tick(packetRateLimit)

	// Wait for data in receive buffer and process
	recvBuffer := make([]byte, 1458)
	for {
		// Wait for the next tick to limit the packet processing rate
		<-rateLimiter

		// Wait for incoming packet and write payload into buffer
		recvDataLen, remoteAddr, err := udpLocalSocket.ReadFromUDP(recvBuffer)
		if err != nil {
			logMessage(fmt.Sprintf("Failed: reading UDP socket resulted in error: %v\n", err))
			continue
		}

		// Read from buffer and clear buffer
		receivedCipherText := recvBuffer[:recvDataLen]

		// Check correct network endpoint
		if remoteAddr.IP.String() != config.RemoteIP || strconv.Itoa(remoteAddr.Port) != config.RemotePort {
			logMessage(fmt.Sprintf("Failed: received Invalid Shutdown Packet from %s:%v. IP or Port incorrect.\n", remoteAddr.IP, remoteAddr.Port))
			continue
		}

		// Decrypt received message
		sessionIV := MutateIVwithTime(encryptionIV)
		plainText, err := AESGCMCipherBlock.Open(nil, sessionIV, receivedCipherText, nil)
		if err != nil {
			logMessage(fmt.Sprintf("Failed: decryption of payload from %s:%v resulted in error: %v\n", remoteAddr.IP, remoteAddr.Port, err))
			continue
		}
		plainTextMessage := string(plainText)

		// If message text is test, log and continue
		if plainTextMessage == TestOnlyFilterMessage {
			_, err := exec.LookPath(filepath.Base(command.Path))
			if err != nil {
				logMessage("Failed: (test) Shutdown executable not found.\n")
			}
			logMessage(fmt.Sprintf("Success: (test) Received Valid Shutdown Packet from %s:%v. Shutdown executable found.\n", remoteAddr.IP, remoteAddr.Port))
			continue
		}

		// Check message validity against config string or validity against the hard coded test message
		if plainTextMessage != config.FilterMessage {
			logMessage(fmt.Sprintf("Failed: received Invalid Shutdown Packet from %s:%v. Message Data is incorrect.\n", remoteAddr.IP, remoteAddr.Port))
			continue
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
					logMessage(fmt.Sprintf("Failed: Pre-check script error: %v\n", err))
					continue
				}
				// Abort shutdown if external script is an error exit (ideally, purposely code 1)
				logMessage("Failed: Aborting shutdown, precheck script shutdown conditions are not met.\n")
				continue
			}
		}

		// Create a buffer to capture stderr
		var stderr bytes.Buffer
		command.Stderr = &stderr

		// Shutdown the system
		logMessage(fmt.Sprintf("Success: Received Valid Shutdown Packet from %s:%v. Initiating system shutdown.\n", remoteAddr.IP, remoteAddr.Port))
		err = command.Run()
		if err == nil {
			break
		}

		logMessage(fmt.Sprintf("Failed: shutdown command resulted in error: %s\n", stderr.String()))
	}
}
