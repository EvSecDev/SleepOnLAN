#!/bin/bash

ActiveUserSubnet="10.0.0."

# If the remote network is connected, disallow shutdown
if [[ $(ss -t state established | grep $ActiveUserSubnet) ]]
then
	exit 1
fi

# If there are logged in users, disallow shutdown
if [[ $(who) ]]
then
	exit 1
fi

# Conditions for shutdown are met, exit with code 0 to allow system shutdown
exit 0
