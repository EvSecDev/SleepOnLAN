# SleepOnLAN
Remote Shutdown Utility made in Go for use on Linux servers.

This program is designed to shutdown a server over the network from a central server as securely as possible.
Think of this as the opposite of WOL (Wake-on-LAN), hence the name SOL (Sleep-on-LAN), but with authentication and encryption.

The functionality provided here is aimed to replace what Network UPS Tools (NUT) does across a network, but with a different, more targeted approach.
Shutdown action is performed over a single unidirectional UDP packet sent to all the servers/devices that need to be shut off.
If more reliability is needed, a TCP mode is optional to ensure shutdown packets arrive.

For security, the program uses a time mutated IV and AES256 GCM encryption to ensure replay attack protection.
With these security features, there is:
- No need (like with NUT) to open holes in firewalls for all clients of a network to communicate with a central server.
- No need for ANY reply traffic from the clients to exist (in UDP mode), which means you can turn off any reply-to auto-rules that your firewall/router may apply to the connection.
- No need to worry about operating over untrusted networks. The client is able to authenticate the server and is protected against replay attacks.

One use case of this program is to integrate into networking monitoring solutions to shutdown down remote hosts when the UPS has low battery.
This is particularly useful when the remote host does not support traditional tooling, such as a Synology NAS.

Notes:
- While this program may work on Windows/BSD, it is not tested, use on non-Linux systems at your own risk.

### Capabilities 

```
Usage: sleeponlan [OPTIONS]...

Examples:
    sleeponlan --config </etc/solconfig.json> --server [--tcp] [--precheck-script </opt/checkforusers.sh>]
    sleeponlan --config </etc/solconfig.json> --client [--tcp] [--remote-hosts <www,proxy,db01>] [--send-test]

Options:
    -c, --config </path/to/json>               Path to the configuration file [default: solconfig.json]
    -C, --client                               Run the client (sending shutdown)
    -S, --server                               Start the server (receiving shutdown)
    -p, --precheck-script </path/to/script>    Run external script prior to shutdown.
                                               If script exits with status code 1, shutdown will be aborted 
    -T, --send-test                            Send test shutdown packet (requires '--client')
    -t, --tcp                                  Use TCP communication for client/server network connections
                                               Does not apply to remote logging IP addresses
    -r, --remote-hosts <IP1,IP2,IP3...>        Override which hosts by IP address from config to send shutdown packet to
    -g, --generate-key                         Generate encryption key for use with server or client
    -V, --version                              Show version and packages
    -v, --versionid                            Show only version number
```

The server and client both utilize the same executable and configuration file.

There is also test functionality built directly into both client and server code.
This is useful since, as a UPS shutdown tool, this program will rarely run but must by ready at all times. 
If you wish to ensure full readiness, run the client with the `--send-test` argument periodically and monitor whichever log you have directed the server to use for the `TEST` messages.

The nature of time-based 'authentication' requires that both the client and server clock be synchronized and within 1 second of each other.
It is recommended to run the aforementioned tests frequently and alert on any message failures to identify potential time synchronization issues.

The time-based authentication is similar to a TOTP code you would find with two factor authentication.
In the case here, the shutdown packet is only valid for 13 seconds (2 second 'no-send' buffer zone to allow for up to 1 second network latency).
This ensures that any commanded shutdown that occurs over an untrusted network cannot be reused in the future by an attacker.

If you desire to check any local system conditions and abort the issued shutdown, the sever can be configured to run an external script to check your desired conditions.
An exit code of 0 from the external script will mean that there are no blocking issues and the server WILL ISSUE a shutdown for the system.
An exit code of 1 from the external script will mean there are blocking issues and the server WILL ABORT a shutdown.

If you have many remote hosts defined in your client configuration, and wish to change which hosts the client sends a shutdown packet to, there is the option `--remote-hosts`.
This option will let you choose which IPs from the client's configuration that will receive a shutdown packet (or test packet).
You only have to provide it with a comma separated list of IP address matching those in the JSON config.

### Deployment

1. Configure the client and server JSON config file with your own network settings, encryptionKey and filterMessage.
  - You can use the program to generate an encryption key or openssl:
    - `./sleeponlan -g`
    - `openssl rand -hex 28`
  - The filterMessage can be whatever text you want, it is only in place to ensure the decryption process also authenticates the client.
2. Copy the binary and JSON config file to wherever you want to initiate the shutdown from.
3. Copy the binary and JSON config file to wherever you want to shutdown.
4. Start the server binary from your terminal or a service with the `--server` argument.
5. Configure whatever triggering action you have to start the binary with the `--client` argument when a server shutdown is desired
  - If multiple remote hosts are desired, use the included example multihost JSON file and add all your server IP/Port pairs in there and use the `--multihost-file` argument with the client.

