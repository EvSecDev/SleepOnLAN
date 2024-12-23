// sleeponlan
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ###################################
//      GLOBAL VARIABLES
// ###################################

type JsonConfig struct {
	ListenIP      string        `json:"listenIP"`
	ListenPort    string        `json:"listenPort"`
	Remote        []RemoteHosts `json:"remote"`
	EncryptionKey string        `json:"encryptionKey"`
	FilterMessage string        `json:"filterMessage"`
	RemoteLog     RemoteLog     `json:"remoteLog"`
	FileLog       FileLog       `json:"fileLog"`
}

type RemoteHosts struct {
	IP   string `json:"IP"`
	Port string `json:"Port"`
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

// For payload parsing
const maxPayloadSize = int(1300)

// For sending test messages
const testMessage = string("deadbeefdeadbeefdeadbeefdeadbeef1928374655647382910")

// For syslog messages
var remoteLogEnabled bool
var syslogAddress *net.UDPAddr

// For file logging
var fileLogEnabled bool
var logFilePath string

// Program Meta Info
const progVersion = string("v1.2.1")
const usage = `
Examples:
    sleeponlan --config </etc/solconfig.json> --server [--tcp] [--precheck-script </opt/checkforusers.sh>]
    sleeponlan --config </etc/solconfig.json> --client [--tcp] [--remote-hosts <www,proxy,db01>] [--send-test]

Options:
    -c, --config </path/to/json>               Path to the configuration file [default: solconfig.json]
    -C, --client                               Run the client (sending shutdown)
    -S, --server                               Start the server (receiving shutdown)
    -p, --precheck-script </path/to/script>    Run external script prior to shutdown (requires '--server')
                                                 If script exits with status code 1, shutdown will be aborted
    -T, --send-test                            Send test shutdown packet (requires '--client')
    -t, --tcp                                  Use TCP communication for client/server network connections
                                                 Does not apply to remote logging IP addresses
    -r, --remote-hosts <IP1,IP2,IP3...>        Override which hosts by IP address from config to send shutdown packet to
    -g, --generate-key                         Generate encryption key for use with server or client
    -V, --version                              Show version and packages
    -v, --versionid                            Show only version number
`

// ###################################
//	START HERE
// ###################################

func main() {
	// Program Argument Variables
	var configFile string
	var clientFlagExists bool
	var serverFlagExists bool
	var sendTest bool
	var useTCP bool
	var hostOverride string
	var externalCheckScript string
	var genNewKey bool
	var versionFlagExists bool
	var versionNumberFlagExists bool

	// Read Program Arguments - allowing both short and long args
	flag.StringVar(&configFile, "c", "solconfig.json", "")
	flag.StringVar(&configFile, "config", "solconfig.json", "")
	flag.BoolVar(&clientFlagExists, "C", false, "")
	flag.BoolVar(&clientFlagExists, "client", false, "")
	flag.BoolVar(&serverFlagExists, "S", false, "")
	flag.BoolVar(&serverFlagExists, "server", false, "")
	flag.StringVar(&externalCheckScript, "p", "", "")
	flag.StringVar(&externalCheckScript, "precheck-script", "", "")
	flag.BoolVar(&sendTest, "T", false, "")
	flag.BoolVar(&sendTest, "send-test", false, "")
	flag.BoolVar(&useTCP, "t", false, "")
	flag.BoolVar(&useTCP, "tcp", false, "")
	flag.StringVar(&hostOverride, "r", "", "")
	flag.StringVar(&hostOverride, "remote-hosts", "", "")
	flag.BoolVar(&genNewKey, "g", false, "")
	flag.BoolVar(&genNewKey, "generate-key", false, "")
	flag.BoolVar(&versionFlagExists, "V", false, "")
	flag.BoolVar(&versionFlagExists, "version", false, "")
	flag.BoolVar(&versionNumberFlagExists, "v", false, "")
	flag.BoolVar(&versionNumberFlagExists, "versionid", false, "")

	// Custom help menu
	flag.Usage = func() { fmt.Printf("Usage: %s [OPTIONS]...\n%s", os.Args[0], usage) }
	flag.Parse()

	// Meta info print out
	if versionFlagExists {
		fmt.Printf("SleepOnLAN %s compiled using %s(%s) on %s architecture %s\n", progVersion, runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("First party packages:\n")
		fmt.Printf("bytes crypto/aes crypto/cipher crypto/rand encoding/binary encoding/hex encoding/json crypto/sha256 runtime flag fmt log/syslog net os os/exec strings time\n")
		os.Exit(0)
	}
	if versionNumberFlagExists {
		fmt.Println(progVersion)
		os.Exit(0)
	}

	var err error

	// New key if user requested
	if genNewKey {
		err = generateNewKey()
		logError("failed to generate new key", err, true)
		os.Exit(0)
	}

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

	// Get cipher block and TOTP from encryption key
	AESGCMCipherBlock, TOTPSecret, err := prepareEncryption(config.EncryptionKey)
	logError("failed to prepare encryption", err, true)

	// Start client or server depending on args
	if clientFlagExists {
		// If test is requested, override message with test string
		if sendTest {
			config.FilterMessage = testMessage
		}

		// Setup Network info
		listenAddress := PairIPPort(config.ListenIP, config.ListenPort)

		// Loop over endpoints in config and send packet
		for arrayPosition, _ := range config.Remote {
			// Override loop with user choices if requested
			var SkipHost bool
			if hostOverride != "" {
				userHostChoices := strings.Split(hostOverride, ",")
				for _, userHostChoice := range userHostChoices {
					// If the users chosen IP is the IP for this loop, then continue to client connection
					if userHostChoice == config.Remote[arrayPosition].IP {
						break
					}
					SkipHost = true
				}
			}
			if SkipHost {
				continue
			}

			// Setup remote address
			remoteAddress := PairIPPort(config.Remote[arrayPosition].IP, config.Remote[arrayPosition].Port)

			// Send packet
			clientConnect(config.FilterMessage, TOTPSecret, AESGCMCipherBlock, listenAddress, remoteAddress, useTCP)
		}
	} else if serverFlagExists {
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

		// Setup Network info
		listenAddress := PairIPPort(config.ListenIP, config.ListenPort)

		// Join exepcted IP and port for compare on connect
		confRemoteAddr := PairIPPort(config.Remote[0].IP, config.Remote[0].Port)

		// Packet processing rate limit - 1 second / 5 packets (200ms in between packets)
		rateLimiter := time.Tick(200 * time.Millisecond)

		// Start the server
		if useTCP {
			serverModeTCP(listenAddress, confRemoteAddr, rateLimiter, externalCheckScript, config.FilterMessage, TOTPSecret, AESGCMCipherBlock, command)
		} else {
			serverModeUDP(listenAddress, confRemoteAddr, rateLimiter, externalCheckScript, config.FilterMessage, TOTPSecret, AESGCMCipherBlock, command)
		}
	} else {
		// If no arguments
		fmt.Printf("No arguments specified! Use '-h' or '--help' to guide your way.\n")
	}
}

// ###################################
//	MISC PARSING
// ###################################

// Based on IPv6 or v4, combines IP and port strings, colon separator
func PairIPPort(IP string, Port string) (IPPort string) {
	if strings.Contains(IP, ":") {
		IPPort = "[" + IP + "]:" + Port
	} else {
		IPPort = IP + ":" + Port
	}
	return
}
