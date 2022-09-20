import kotlinx.cinterop.*
import platform.darwin.*
import platform.posix.*
import sockets.*

// Just to avoid import conflict.
typealias sockaddr_in = platform.posix.sockaddr_in
typealias sockaddr_in6 = platform.posix.sockaddr_in6


data class Args(
    val host: String,
    val port: Int,
    val packetSize: Int,
    val maxHops: Int,
    val timeout: Int,
    val firstHop: Int,
    val retries: Int
) {}

fun identifyHost(host: String): String? {
    memScoped {
        val info = nativeHeap.allocPointerTo<addrinfo>()
        val hints = alloc<addrinfo>()
        memset(hints.ptr, 0, sizeOf<addrinfo>().convert())
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = 0;
        val result = getaddrinfo(host, "http", hints.ptr, info.ptr)
        if (result != 0) {
            println("error looking up hostname: ${gai_strerror(result)}")
        }
        var res: CPointer<addrinfo>? = info.value
        var cause = "start"
        while (res != null && res.pointed.ai_next != null) {
            val ai = res.pointed
            val s = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol)
            if (s < 0) {
                cause = "socket"
                res = ai.ai_next
                continue
            }

            if (connect(s, ai.ai_addr, ai.ai_addrlen) < 0) {
                cause = "connect"
                close(s)
                res = ai.ai_next
                continue
            }

            break
        }
        if (res != null) {
            val address = res.pointed.ai_addr?.let { getAddress(it.pointed) }
            if (address != null) {
                return address
            }
        }
        return null
    }
}

fun getTime(): timespec {
    memScoped {
        val spec = alloc<timespec>()
        clock_gettime(CLOCK_MONOTONIC, spec.ptr)
        return spec
    }
}

fun getElapsedTimeMs(start: timespec, end: timespec): ULong {
    var resultMs = (end.tv_sec - start.tv_sec).toULong() * 1000u
    resultMs += (end.tv_nsec - start.tv_nsec).toULong() / 1000u
    return resultMs
}


fun getAddress(addr: sockaddr): String? {
    return when (addr.sa_family.toInt()) {
        AF_INET -> {
            val s = ByteArray(INET_ADDRSTRLEN)
            val saIn = addr.reinterpret<sockaddr_in>()
            s.usePinned { pinned ->
                val res = inet_ntop(AF_INET, saIn.sin_addr.ptr, pinned.addressOf(0), INET_ADDRSTRLEN);
                if (res == null) {
                    println("failed to convert addr")
                    println("err: ${getErrno()}")
                }
                s.decodeToString()
            }
        }
        AF_INET6 -> {
            val s = ByteArray(INET6_ADDRSTRLEN)
            val saIn = addr.reinterpret<sockaddr_in6>()
            s.usePinned { pinned ->
                val res = inet_ntop(AF_INET6, saIn.sin6_addr.ptr, pinned.addressOf(0), INET6_ADDRSTRLEN);
                if (res == null) {
                    println("failed to convert addr")
                    println("err: ${getErrno()}")
                }
                s.decodeToString()
            }
        }
        else -> null
    }
}

sealed class ProbeResult {
    data class SuccessfulHop(val address: String, val time: ULong): ProbeResult()
    data class Done(val address: String, val time: ULong): ProbeResult()
    data class Timeout(val info: String): ProbeResult()
    data class Failure(val info: String): ProbeResult()
}

fun probeHop(
    port: UShort,
    address: String,
    timeoutMs: Int,
    currentTtl: Int,
    packetSize: Int,
    targetAddress: String
): ProbeResult {
    memScoped {
        val serverAddr = alloc<sockaddr_in>()
        memset(serverAddr.ptr, 0, sizeOf<sockaddr_in>().convert());
        serverAddr.sin_family = AF_INET.convert()
        serverAddr.sin_addr.s_addr = inet_addr(address)
        serverAddr.sin_port = port
        val serverAddrSize = sizeOf<sockaddr_in>().convert<socklen_t>()
        val sockAddr = serverAddr.ptr.reinterpret<sockaddr>()
        // Set up the socket to receive inbound packets
        val recvSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        bind(recvSocket, sockAddr, serverAddrSize)

        val timeval = alloc<timeval>()
        with (timeval) {
            this.tv_sec = 0
            this.tv_usec = timeoutMs * 1000
        }
        setsockopt(recvSocket, SOL_SOCKET, SO_RCVTIMEO, timeval.ptr, sizeOf<timeval>().convert())

        // Set up the socket to send packets out
        val sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        bind(sendSocket, sockAddr, serverAddrSize)
        // This sets the current hop TTL
        setsockopt(sendSocket, IPPROTO_IP, IP_TTL, cValuesOf(currentTtl), sizeOf<IntVar>().convert())

        println("sendSocket=$sendSocket")
        println("recvSocket=$recvSocket")

        // Send a single null byte UDP packet
        val payload = byteArrayOf(0x0)
        val error = sendto(sendSocket, allocArrayOf(payload), 0, 0, sockAddr, serverAddrSize)
        if (error == -1L) {
            return ProbeResult.Failure("error sending UDP packet, errno:${getErrno()}")
        }

        val buf = ByteArray(packetSize)
        val recvAddr = alloc<sockaddr>()
        val err = recvfrom(recvSocket, buf.toCValues(), buf.size.convert(),0, recvAddr.ptr,
            cValuesOf(sizeOf<sockaddr>().toUInt()))
        close(recvSocket)
        close(sendSocket)
        if (err == -1L) {
            val errno = getErrno()
            if (errno == 35) {
                return ProbeResult.Timeout("timed out")
            }
            return ProbeResult.Failure("error receiving packet, errno:$errno")
        }
        val recvAddress = getAddress(recvAddr)
        if (recvAddress != null) {
            return if (recvAddress == targetAddress) {
                ProbeResult.Done(recvAddress, 0u) // TODO: time
            } else {
                ProbeResult.SuccessfulHop(recvAddress,0u) // TODO: time
            }
        }
        return ProbeResult.Failure("address not found in response")
    }
}

fun traceroute(args: Args) {
    val maxHops = args.maxHops
    val port = interop_htons(args.port.toUShort())
    var currentTtl = args.firstHop
    val address = identifyHost(args.host) ?: throw Exception("failed to get an address")
    println("address: $address, port: ${args.port}")
    var retries = 0
    while (true) {
        println("currentTtl:$currentTtl")
        val probeResult = probeHop(
            timeoutMs = args.timeout,
            port = port,
            address = address,
            currentTtl = currentTtl,
            packetSize = args.packetSize,
            targetAddress = address
        )
        when (probeResult) {
            is ProbeResult.Failure -> {
                println("failed: ${probeResult.info}")
                return
            }
            is ProbeResult.Done -> {
                println("finished")
                return
            }
            is ProbeResult.SuccessfulHop -> {
                currentTtl += 1
                println("hop ${currentTtl}, ${probeResult.address}: ${probeResult.time}ms")
            }
            is ProbeResult.Timeout -> {
                if (retries >= args.retries) {
                    retries = 0
                    currentTtl += 1
                }
                retries += 1
            }
        }
        if (currentTtl >= maxHops) {
            println("hit max hops")
            return
        }
    }
}