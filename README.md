# SleepOnLAN
Remote Shutdown Utility made in Go for use on Linux servers.

This program is designed to shutdown a server over the network from a central server as securely as possible.
Think of this as the opposite of WOL (Wake-on-LAN) with authentication and encryption, hence the name SOL (Sleep-on-LAN).

The functionality provided here is aimed to replace what Network UPS Tools (NUT) does across a network, but with a different, more targeted approach.
Shutdown action is performed over a single unidirectional UDP packet sent to all the servers/devices that need to be shut off.

For security, the program uses a time mutated IV and AES256 GCM encryption to ensure replay attack protection.
With these security features, there is:
- No need (like with NUT) to open holes in firewalls for all clients of a network to communicate with a central server.
- No need for ANY reply traffic from the clients to exist, which means you can turn off any reply-to auto-rules that your firewall/router may apply to the connection.
- No need to worry about operating over untrusted networks. The client is able to authenticate the server and is protected against replay attacks.

One use case of this program is to integrate into networking monitoring solutions to shutdown down remote hosts when the UPS has low battery.
This is particularly useful when the remote host does not support traditional tooling, such as a Synology NAS.

Notes:
- The high security of this tool with its single unidirectional packet means that network links that suffer from packet loss or degradation should be avoided.
- While this program may work on Windows/BSD, it is not tested, use on non-Linux systems at your own risk.

### Capabilities 

```
Usage of sleeponlan:
-V				Print Version Information
-c [string]			Path to the configuration file (default "solconfig.json")
-client				Run the client (sending shutdown) 
-server				Start the server (receiving shutdown)
-send-test			Send test shutdown packet (requires --client)
-multihost-file [string]	Override single host with array of hosts in file (requires --client)
-precheck-script [string]	Run external script prior to shutdown. If script exits with code 1, shutdown will be aborted. (requires --server)
```

The server and client both utilize the same executable and configuration file.
In order to use the client mode with many remote servers, a separate JSON file containing an array of IP/Port pairs must be used.

There is also test functionality built directly into both client and server code.
This is useful since, as a UPS shutdown tool, this program will rarely run but must by ready at all times. 
If you wish to ensure full readiness, run the client with the `--send-test` argument periodically and monitor whichever log you have directed the server to use for the `TEST` messages.

The nature of time-based 'authentication' requires that both the client and server be synchronized and within 1 second of each other.
It is recommended to run the aforementioned tests frequently and alert on any message failures to identify potential time synchronization issues.

The time-based authentication is similar to a TOTP code you would find with two factor authentication.
In the case here, the shutdown packet is only valid for 13 seconds (2 second 'no-send' buffer zone to allow for up to 1 second network latency).
This ensures that any commanded shutdown that occurs over an untrusted network cannot be reused in the future by an attacker (after the remote host is powered back on).

If you desire to check any local system conditions and abort the issued shutdown, the sever can be configured to run an external script to check your desired conditions.
An exit code of 0 from the external script will mean that there are no blocking issues and the server WILL ISSUE a shutdown for the system.
An exit code of 1 from the external script will mean there are blocking issues and the server WILL ABORT a shutdown.

### Deployment

1. Configure the client and server JSON config file with your own network settings, Key, IV, and filterMessage.
  - You can use openssl to generate a Key and IV:
    - Key: `openssl rand -hex 16`
    - IV: `openssl rand -hex 12`
  - The filterMessage can be whatever text you want, it is only in place to ensure the decryption process also authenticates the client.
2. Copy the binary and JSON config file to wherever you want to initiate the shutdown from.
3. Copy the binary and JSON config file to wherever you want to shutdown.
4. Start the server binary from your terminal or a service with the `--server` argument.
5. Configure whatever triggering action you have to start the binary with the `--client` argument when a server shutdown is desired
  - If multiple remote hosts are desired, use the included example multihost JSON file and add all your server IP/Port pairs in there and use the `--multihost-file` argument with the client.
