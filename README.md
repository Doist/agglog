This is a basic service allowing one to "tail" logs from multiple servers without the need to log into them.

Central "server" instance exposes two endpoints: one for viewers (people), another one for collectors — client agents running on servers.

Client agents running on servers connect to central server, notify server of their hostname and list of published log files, then keep their session alive waiting for requests from the server.

When user requests server to display list of known servers or their logs, it shows this information based on currently connected clients.

When user requests server to display certain log, server sends this request over existing session to client, client fetches few last kilobytes of data from the log file and sends it back to the server, which then sends it to the user.

To run server (centralized) instance:

	agglog server \
		-addr.public=$USER_FACING_ADDR \
		-addr.sink=$AGENT_FACING_ADDR \
		-auth=$AUTH_HASH

Here `$USER_FACING_ADDR` is an http endpoint to be accessed by users. `$AGENT_FACING_ADDR` is an http (websocket) endpoint where agent clients connect to. `$AUTH_HASH` is a hex-encoded sha256 sum of `username:password` combination used for basic authorization (only for users). Note that if `-auth` flag is left empty, no authorization is required. It is also possible to set this value with `AGGLOG_AUTH` environment variable.

To run client (agent running on each server with logs):

	agglog client -addr=$ADDR /path/to/log1 /path/to/log2 ...

Here `$ADDR` is address of server (`-addr.sink` flag on the server). Note that it can be of basic host:port form, or url like `ws://host:port`. If you have https-proxy in front of websocket server endpoint, use `wss://host:port` format.

This tool is intentioanlly kept basic and is expected to be run in a trusted environment. If you need to expose it over internet, it is advised to put https-terminating proxy in front of it.