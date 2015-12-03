# StartTLS Strip

### A few notes on design

What the code will have to do:

1. It essentially works as a man-in-the-middle proxy modifying relevant traffic
2. Relevant traffic is messages used to switch from insecure to secure connections via STARTTLS
3. By default listen on the FTP, TELNET, SMTP, IMAP and XMPP
4. Alternatively, the user can choose which specific protocol he wants to strip

First thing to implement is the basic functionality of MITM proxy. After implementing it properly,
expand it to use select() to poll between all protocols sockets.

NOTE: Just realized that using select() it will be required to know the destination (server) host.
This is impractical for many cases. Let's use Twisted instead.

### Twisted notes

Protocol handling class usually subclasses `twisted.internet.protocol.Protocol`. Persistent
onfiguration is kept in `Factory`  which inherits from `twisted.internet.protocol.Factory`.
The `buildProtocol` method of Factory is used to create a new Protocol for each new connection

Factory does not listen to connections and does not know anything about the network.

- `connectionMade` event is where the setup of the connection happens.
- `connectionLost` event is where tearing down happens.
- `dataReceived` event is when data is received through the network.

In all honesty, we don't need any of this knowledge. All we will focus on is `portforward.Proxy.dataReceived`
for data received, and set the correct callback functions for `portforward.ProxyServer.dataReceived` and
`portforward.ProxyClient.dataReceived`.

Example:

```python
portforward.ProxyClient.dataReceived = handle_client
in handle_client:
handle_client(self, data):
...
	portforward.Proxy.dataReceived(self, data)

reactorListenTCP(localport, portforward.ProxyFactory(desthost, destport)
```

Additional notes: http://blog.ziade.org/2010/09/30/twisted-rocks/
