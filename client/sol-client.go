// sol-client
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"os"
	"strings"
)

type parseJsonConfig struct {
	ListenIP        string `json:"listenIP"`
	ListenPort      string `json:"listenPort"`
	DestinationIP   string `json:"destinationIP"`
	DestinationPort string `json:"destinationPort"`
	Key             string `json:"Key"`
	IV              string `json:"IV"`
	CurrentCounter  int    `json:"currentCounter"`
	Message         string `json:"sendMessage"`
	SyslogIP        string `json:"syslogDestinationIP"`
	SyslogPort      string `json:"syslogDestinationPort"`
}

func sendErrorToSyslog(syslogAddress *net.UDPAddr, errorDescription string, errorMessage error) {
	if errorMessage != nil {
		message := errorDescription + ": " + errorMessage.Error()
		sendSyslogMessage(syslogAddress, message)
	}
}

func sendSyslogMessage(syslogAddress *net.UDPAddr, message string) error {
	conn, err := net.DialUDP("udp", nil, syslogAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	priority := syslog.LOG_INFO
	tag := "sol-client"
	syslogMsg := fmt.Sprintf("<%d>%s: %s", priority, tag, message)

	_, err = conn.Write([]byte(syslogMsg))
	if err != nil {
		return err
	}

	return nil
}

func MutateIVwithCounter(encryptionIV []byte, CurrentCounter int) []byte {
	counterBytes := make([]byte, 4)
	for i := uint(0); i < 4; i++ {
		counterBytes[i] = byte(CurrentCounter >> (8 * i))
	}

	copy(encryptionIV[len(encryptionIV)-4:], counterBytes)
	return encryptionIV[:12]
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "sol-client.json", "Path to the configuration file")
	flag.Parse()

	// Grab configuration options from file
	jsonConfigFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal("Error reading config file: ", err)
		return
	}
	var config parseJsonConfig
	err = json.Unmarshal(jsonConfigFile, &config)
	if err != nil {
		log.Fatal("Error parsing JSON config: ", err)
		return
	}

	// Setup Remote Logging
        var syslogAddress *net.UDPAddr
        if strings.Contains(config.ListenIP, ":") {
                syslogAddress, err = net.ResolveUDPAddr("udp", "["+config.SyslogIP+"]:"+config.SyslogPort)
        } else {
                syslogAddress, err = net.ResolveUDPAddr("udp", config.SyslogIP+":"+config.SyslogPort)
        }

	if err != nil {
		log.Fatal("Error resolving syslog address:", err)
		return
	}

	// Encryption
	if len(config.Key) != 32 {
		message := fmt.Sprintf("Invalid key size: The key must be 32 bytes (256-bit) for AES-256, but the key is %d bytes.", len(config.Key))
		sendSyslogMessage(syslogAddress, message)
		return
	}
	if len(config.IV) != 12 {
		message := fmt.Sprintf("Invalid IV size: The IV must be 12 bytes (96-bit) for AES-256, but the IV is %d bytes.", len(config.IV))
		sendSyslogMessage(syslogAddress, message)
		return
	}

	plainTextMessage := []byte(config.Message)

	encryptionKey, err := hex.DecodeString(config.Key)
	sendErrorToSyslog(syslogAddress, "Error decoding key", err)

	encryptionIV, err := hex.DecodeString(config.IV)
	sendErrorToSyslog(syslogAddress, "Error decoding IV", err)

	CipherBlock, err := aes.NewCipher(encryptionKey)
	sendErrorToSyslog(syslogAddress, "Error creating cipher block", err)

	AESGCMCipherBlock, err := cipher.NewGCM(CipherBlock)
	sendErrorToSyslog(syslogAddress, "Error creating AES-GCM cipher", err)

	sessionIV := MutateIVwithCounter(encryptionIV, config.CurrentCounter)
	CipherText := AESGCMCipherBlock.Seal(nil, sessionIV, plainTextMessage, nil)
	sendMessage := hex.EncodeToString(CipherText)

	// Network
        var listenAddress string
	var destinationAddress string
        if strings.Contains(config.ListenIP, ":") {
                listenAddress = "["+config.ListenIP+"]:"+config.ListenPort
        } else {
                listenAddress = config.ListenIP+":"+config.ListenPort
        }

        if strings.Contains(config.ListenIP, ":") {
                destinationAddress = "["+config.DestinationIP+"]:"+config.DestinationPort
        } else {
                destinationAddress = config.DestinationIP+":"+config.DestinationPort
        }

	udpLocalSocket, err := net.ListenPacket("udp", listenAddress)
	sendErrorToSyslog(syslogAddress, "Error creating local UDP socket", err)
	defer udpLocalSocket.Close()

	udpRemoteSocket, err := net.ResolveUDPAddr("udp", destinationAddress)
	sendErrorToSyslog(syslogAddress, "Error resolving destination address", err)

	_, err = udpLocalSocket.WriteTo([]byte(sendMessage), udpRemoteSocket)
	sendErrorToSyslog(syslogAddress, "Error sending message", err)

	message := fmt.Sprintf("Sent Shutdown Packet to %s.", destinationAddress)
	sendSyslogMessage(syslogAddress, message)
	udpLocalSocket.Close()

	// Save Current Counter
	config.CurrentCounter++

	updatedJSONData, err := json.MarshalIndent(config, "", "  ")
	sendErrorToSyslog(syslogAddress, "Error marshaling to JSON", err)

	err = ioutil.WriteFile(configFile, updatedJSONData, 0640)
	sendErrorToSyslog(syslogAddress, "Error writing to config file", err)

	os.Exit(0)
}
