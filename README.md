# SleepOnLAN
Remote Shutdown Utility made in Go for use on Debian and Debian-like servers.

This program is designed to securely shutdown a Linux server over the network from another Linux server with as little code and permissions as possible.
Shutdown action is performed securely over a single unidirectional UDP packet, utilizing One-Time-Pad (OTP) and AES256 GCM encryption to ensure replay attack protection.

One use case of this program is to integrate into networking monitoring solutions to shutdown down remote hosts when the UPS has low battery. 

This is a very early prototype and currently only supports a single endpoint to shutdown. Use at your own risk.

### Deployment

1. Copy the client binary and JSON config file over to wherever you want to initiate the shutdown from.
2. Copy the server binary and JSON config file over to wherever you want to shutdown.
3. Configure the client and server JSON config file with your own network settings, Key, IV, and sendMessage.
4. Kick off the server binary from your terminal or a service.
5. Configure whatever triggering action you have to start the client binary when a server shutdown is desired.
