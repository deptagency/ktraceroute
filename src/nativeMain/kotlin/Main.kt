import platform.posix.*
import platform.darwin.*
import kotlinx.cinterop.*
import sockets.interop_htons

// Just to avoid import conflict.
typealias sockaddr_in = platform.posix.sockaddr_in

const val DEFAULT_PORT = 33434
const val DEFAULT_MAX_HOPS = 64
const val DEFAULT_FIRST_HOP = 1
const val DEFAULT_TIMEOUT_MS = 500
const val DEFAULT_RETRIES = 3
const val DEFAULT_PACKET_SIZE = 52

fun getNSPort(): UShort {
    // alternatively: ((port shr 8) or ((port and 0xff) shl 8)).toUShort()
    // "htons: host byte order to network byte order, short"
    return interop_htons(DEFAULT_PORT.toUShort())
}

fun getPacketSize(): Int {
    return DEFAULT_PACKET_SIZE
}

fun main() {
    val endpoint ="127.0.0.1"
    val ttl = 5
    println("port: ${getNSPort()}")
    memScoped {
        val serverAddr = alloc<sockaddr_in>()
        memset(serverAddr.ptr, 0, sizeOf<sockaddr_in>().convert());
        serverAddr.sin_family = AF_INET.convert()
        serverAddr.sin_addr.s_addr = inet_addr(endpoint)
        serverAddr.sin_port = getNSPort()

        val serverAddrSize = sizeOf<sockaddr_in>().convert<socklen_t>()
        val sockAddr = serverAddr.ptr.reinterpret<sockaddr>()
        // Set up the socket to receive inbound packets
        val recvSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        bind(recvSocket, sockAddr, serverAddrSize)

        val timeoutUs = 100;
        val timeval = alloc<timeval>()
        with (timeval) {
            this.tv_sec = 0
            this.tv_usec = timeoutUs
        }
        setsockopt(recvSocket, SOL_SOCKET, SO_RCVTIMEO, timeval.ptr, sizeOf<timeval>().convert())

        // Set up the socket to send packets out
        val sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        bind(sendSocket, sockAddr, serverAddrSize)
        // This sets the current hop TTL
        setsockopt(sendSocket, 0, IP_TTL, cValuesOf(ttl), sizeOf<IntVar>().convert())

        println("sendSocket=$sendSocket")
        println("recvSocket=$recvSocket")

        // Send a single null byte UDP packet
        // syscall.Sendto(sendSocket, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: options.Port(), Addr: destAddr})
        val payload = byteArrayOf(0x0)
        val error = sendto(sendSocket, allocArrayOf(payload), 0, 0, sockAddr, serverAddrSize)
        if (error == -1L) {
            println("error sending UDP packet, errno:$error")
        }

        val buf = ByteArray(getPacketSize())
        for ()

        close(recvSocket)
        close(sendSocket)
    }
}