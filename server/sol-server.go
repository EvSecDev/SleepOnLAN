// sol-server
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
	"os/exec"
	"strconv"
)

type parseJsonConfig struct {
	ListenIP            string `json:"listenIP"`
	ListenPort          string `json:"listenPort"`
	FilterSourceIP      string `json:"filterSourceIP"`
	FilterSourcePort    string `json:"filterSourcePort"`
	Key                 string `json:"Key"`
	IV                  string `json:"IV"`
	CurrentCounter      int    `json:"currentCounter"`
	FilterSourceMessage string `json:"filterSourceMessage"`
	SyslogIP            string `json:"syslogDestinationIP"`
	SyslogPort          string `json:"syslogDestinationPort"`
}

func sendErrorToSyslog(syslogAddress *net.UDPAddr, errorDescription string, errorMessage error) {
	if errorMessage != nil {
		message := errorDescription + ": " + errorMessage.Error()
		sendSyslogMessage(syslogAddress, message)
	}
}

func sendSyslogMessage(syslogAddress *net.UDPAddr, message string) error {
	udpLocalSocket, err := net.DialUDP("udp4", nil, syslogAddress)
	if err != nil {
		return err
	}
	defer udpLocalSocket.Close()

	priority := syslog.LOG_INFO
	tag := "sol-server"
	syslogMsg := fmt.Sprintf("<%d>%s: %s", priority, tag, message)

	_, err = udpLocalSocket.Write([]byte(syslogMsg))
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

func decryptMessage(syslogAddress *net.UDPAddr, CipherText, Key []byte, sessionIV []byte) string {
	CipherBlock, err := aes.NewCipher(Key)
	sendErrorToSyslog(syslogAddress, "Error creating cipher block", err)

	AESGCMCipherBlock, err := cipher.NewGCM(CipherBlock)
	sendErrorToSyslog(syslogAddress, "Error creating AES-GCM cipher", err)

	plainText, err := AESGCMCipherBlock.Open(nil, sessionIV, CipherText, nil)
	sendErrorToSyslog(syslogAddress, "Error decrypting Cipher Text", err)

	plainTextMessage := string(plainText)
	return plainTextMessage
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "sol-server.json", "Path to the configuration file")
	flag.Parse()

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

	syslogAddress, err := net.ResolveUDPAddr("udp4", config.SyslogIP+":"+config.SyslogPort)
	if err != nil {
		log.Fatal("Error resolving syslog address: ", err)
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

	encryptionKey, err := hex.DecodeString(config.Key)
	sendErrorToSyslog(syslogAddress, "Error decoding key", err)

	encryptionIV, err := hex.DecodeString(config.IV)
	sendErrorToSyslog(syslogAddress, "Error decoding IV", err)

	// Network
	listenAddress, err := net.ResolveUDPAddr("udp4", config.ListenIP+":"+config.ListenPort)
	sendErrorToSyslog(syslogAddress, "Error compiling address IP and Port pair", err)

	udpLocalSocket, err := net.ListenUDP("udp4", listenAddress)
	sendErrorToSyslog(syslogAddress, "Error creating UDP socket", err)
	defer udpLocalSocket.Close()

	recvbuffer := make([]byte, 1024)
	for {
		recvdata, remoteAddr, err := udpLocalSocket.ReadFromUDP(recvbuffer)
		sendErrorToSyslog(syslogAddress, "Error reading from UDP socket buffer", err)

		// Check correct network endpoint
		if remoteAddr.IP.String() != config.FilterSourceIP || strconv.Itoa(remoteAddr.Port) != config.FilterSourcePort {
			message := fmt.Sprintf("Received Invalid Shutdown Packet from %s:%v. IP or Port incorrect.\n", remoteAddr.IP, remoteAddr.Port)
			sendSyslogMessage(syslogAddress, message)
			continue
		}

		// Encryption
		receivedMessage := string(recvbuffer[:recvdata])
		CipherText, err := hex.DecodeString(receivedMessage)
		sendErrorToSyslog(syslogAddress, "Error decoding received message", err)

		sessionIV := MutateIVwithCounter(encryptionIV, config.CurrentCounter)
		plainTextMessage := decryptMessage(syslogAddress, CipherText, encryptionKey, sessionIV)

		// Check message validity
		if plainTextMessage != config.FilterSourceMessage {
			message := fmt.Sprintf("Received Invalid Shutdown Packet from %s:%v. Message Data is incorrect.\n", remoteAddr.IP, remoteAddr.Port)
			sendSyslogMessage(syslogAddress, message)
			continue
		}

		message := fmt.Sprintf("Received Valid Shutdown Packet from %s:%v. Powering off...\n", remoteAddr.IP, remoteAddr.Port)
		sendSyslogMessage(syslogAddress, message)

		// Save Current Counter
		config.CurrentCounter++

		updatedJSONData, err := json.MarshalIndent(config, "", "  ")
		sendErrorToSyslog(syslogAddress, "Error marshaling to JSON", err)

		err = ioutil.WriteFile(configFile, updatedJSONData, 0640)
		sendErrorToSyslog(syslogAddress, "Error writing to config file", err)

		// Execute OS Command
		cmd := exec.Command("/sbin/poweroff", "-p")

		done := make(chan error)
		err = cmd.Start()
		sendErrorToSyslog(syslogAddress, "Error running reboot command", err)

		go func() {
			done <- cmd.Wait()
		}()
		err = <-done
		sendErrorToSyslog(syslogAddress, "Reboot command execution error", err)
	}
}
