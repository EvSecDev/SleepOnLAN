// sleeponlan
package main

import (
	"fmt"
	"log/syslog"
	"net"
	"os"
	"time"
)

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
