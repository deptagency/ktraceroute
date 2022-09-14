import asyncio
import random
import socket


def get_addr(addr):
    hostname, port = addr
    print(port)
    return hostname, socket.htons(port)


class EchoServerProtocol:
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = data.decode()
        print('Received %r from %s' % (message, get_addr(addr)))
        rand = random.randint(0, 10)
        if rand >= 4:
            print('Send %r to %s' % (message, get_addr(addr)))
            self.transport.sendto(data, addr)
        else:
            print('Send %r to %s' % (message, get_addr(addr)))
            self.transport.sendto(data, addr)


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