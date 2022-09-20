import asyncio
import random
import socket


class EchoServerProtocol:
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = data.decode()
        print('Received %r from %s' % (message, addr))
        print('Send %r to %s' % (b"a"*64, addr))
        self.transport.sendto(b"a"*64, addr)


loop = asyncio.get_event_loop()
print("Starting UDP server")

# One protocol instance will be created to serve all client requests
listen = loop.create_datagram_endpoint(EchoServerProtocol, local_addr=('127.0.0.1', 8008))
transport, protocol = loop.run_until_complete(listen)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

transport.close()
loop.close()