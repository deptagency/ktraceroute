import kotlinx.cinterop.*
import kotlinx.cinterop.ByteVar
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

fun getInterfaceSockaddr(name: String): sockaddr_in? {
    memScoped {
        val addrs = nativeHeap.allocPointerTo<ifaddrs>()
        if (getifaddrs(addrs.ptr) == -1) {
            return null
        }
        var addrsIt: CPointer<ifaddrs>? = addrs.value
        while (addrsIt != null) {
            val ifaAddr = addrsIt.pointed.ifa_addr?.pointed
            val saFamily = ifaAddr?.sa_family?.toInt()
            val ifaName = addrsIt.pointed.ifa_name?.toKString()
            if (name == ifaName) {
                when (saFamily) {
                    AF_INET -> {
                        return ifaAddr.reinterpret()
                    }
                }
            }
            addrsIt = addrsIt.pointed.ifa_next
        }
        return null
    }
}

fun identifyHost(host: String): CPointer<sockaddr>? {
    memScoped {
        val info = nativeHeap.allocPointerTo<addrinfo>()
        val hints = alloc<addrinfo>()
        memset(hints.ptr, 0, sizeOf<addrinfo>().convert())
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = 0
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
        return res?.pointed?.ai_addr
    }
}

fun getTime(): timespec {
    memScoped {
        val spec = nativeHeap.alloc<timespec>()
        clock_gettime(CLOCK_MONOTONIC, spec.ptr)
        return spec
    }
}

fun getElapsedTimeMs(start: timespec, end: timespec): Float {
    var resultMs = (end.tv_sec - start.tv_sec).toFloat() * 1000f
    resultMs += (end.tv_nsec - start.tv_nsec).toFloat() / (1000000.000f)
    return resultMs
}

fun checkRoot() {
    if (getuid() != 0u) {
        println("This program must be run with root to use raw sockets.")
    }
}

fun getInAddr(addr: sockaddr): in_addr? {
    return when (addr.sa_family.toInt()) {
        AF_INET -> {
            val saIn = addr.reinterpret<sockaddr_in>()
            return saIn.sin_addr
        }
//        AF_INET6 -> {
//            val s = ByteArray(INET6_ADDRSTRLEN)
//            val saIn = addr.reinterpret<sockaddr_in6>()
//            s.usePinned { pinned ->
//                return saIn.sin6_addr
//            }
//        }
        else -> null
    }
}

fun getAddressStr(addr: sockaddr): String? {
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
    data class SuccessfulHop(val address: String, val time: Float): ProbeResult()
    data class Done(val address: String, val time: Float): ProbeResult()
    data class Timeout(val info: String): ProbeResult()
    data class Failure(val info: String): ProbeResult()
}

@OptIn(ExperimentalUnsignedTypes::class)
fun probeHop(
    port: UShort,
    destination: sockaddr,
    destinationStr: String,
    timeoutMs: Int,
    currentTtl: Int,
    packetSize: Int
): ProbeResult {
    memScoped {
        // Set up the socket to receive inbound packets
        val recvSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        bind(recvSocket, destination.ptr, sizeOf<sockaddr>().convert())

        val data = "TEST".cstr
        val ip4HdrLen = 20L // raise if using header options
        val icmpHdrLen = 8L // likewise we only send this many bytes, despite there being more in icmp struct
        val dataLen = data.size.toLong()
        val bufferSize = ip4HdrLen + icmpHdrLen + dataLen
        val sendBuf = nativeHeap.allocArray<ByteVar>(bufferSize)
        val icmp = getIcmp(0x1, 0x9)
        val ip = getIp(bufferSize.toUShort(), currentTtl.toUByte())
        val srcAddr = getInterfaceSockaddr("en0") ?: run {
            return ProbeResult.Failure("failed to get interface (for setting packet source)")
        }
        val destAddr = getInAddr(destination) ?: run {
            return ProbeResult.Failure("") // todo: write error string
        }

        ip.pointed.ip_dst.s_addr = destAddr.s_addr
        ip.pointed.ip_src.s_addr = srcAddr.sin_addr.s_addr
        // set ip hdr checksum
        ip.pointed.ip_sum = checksum(ip.reinterpret(), ip4HdrLen.toInt())
        memcpy(sendBuf, ip, ip4HdrLen.toULong())
        memcpy(sendBuf+ip4HdrLen, icmp, icmpHdrLen.toULong())
        memcpy(sendBuf+ip4HdrLen+icmpHdrLen, data.ptr, data.size.toULong())
        icmp.pointed.icmp_cksum = checksum((sendBuf+ip4HdrLen)!!.reinterpret(), (icmpHdrLen + data.size).toInt())
        memcpy(sendBuf+ip4HdrLen, icmp, icmpHdrLen.toULong())

        val sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
        if (sd < 0) {
            return ProbeResult.Failure("failed to get outbound socket descriptor")
        }

        val soResult = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, cValuesOf(1), sizeOf<IntVar>().convert())
        if (soResult < 0) {
            return ProbeResult.Failure("failed to set IP_HDRINCL sockopt:${strerror(getErrno())?.toKString()}")
        }

//        // Bind socket to interface index.
//        // for linux:
//        if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
//
//        }
//        // for mac:
//        if (setsockopt (sd, SOL_SOCKET, IP_BOUND_IF, &ifr, sizeof (ifr)) < 0) {
//
//        }
//        inet_ntoa(destination.reinterpret<in_addr>().readValue())?.let { println(it.toKString()) }

        // send packet
        // if we're going to use sendto, we don't need to connect...either connect & send _or_ sendto
        val error = sendto(sd, sendBuf, bufferSize.toULong(), 0, destination.ptr, sizeOf<sockaddr>().convert())
        if (error < 0L) {
            return ProbeResult.Failure("error sending packet: ${strerror(getErrno())?.toKString()}")
        }
        val t1 = getTime()

        // wait for response
        val timeval = alloc<timeval>()
        timeval.tv_sec = 5
        timeval.tv_usec = 0
        val fdSet = alloc<fd_set>()
        posix_FD_ZERO(fdSet.ptr)
        posix_FD_SET(recvSocket, fdSet.ptr)
        fcntl(recvSocket, F_SETFL, O_NONBLOCK)
        val retval = select(sd+1, fdSet.ptr, null, null, timeval.ptr);
        if (retval == -1) {
            return ProbeResult.Failure("failed to receive response")
        }
//        } else if (retval == 0) {
//            return ProbeResult.Timeout("receiving response timed out")
//        }
        val buf = ByteArray(IP_MAXPACKET)
        val recvAddr = alloc<sockaddr>()
        val recvSocklen: socklen_t = sizeOf<sockaddr>().convert()
        val bytes = recvfrom(recvSocket, buf.refTo(0), buf.size.toULong(),0, recvAddr.ptr, cValuesOf(recvSocklen))
        close(recvSocket)
        close(sd)
        if (bytes == -1L) {
            val errno = getErrno()
            if (errno == 35) {
                return ProbeResult.Timeout("timed out")
            }
            return ProbeResult.Failure("error receiving packet, errno:$errno")
        }
        val recvIphdr = buf.refTo(0).getPointer(this).reinterpret<ip>().pointed
        val recvIcmphdr = buf.refTo(ip4HdrLen.toInt()).getPointer(this).reinterpret<icmp>().pointed
        if (
            (recvIphdr.ip_p == IPPROTO_ICMP.toUByte()) &&
            (recvIcmphdr.icmp_type == ICMP_TIMXCEED.toUByte()) &&
            (recvIcmphdr.icmp_code == ICMP_TIMXCEED_INTRANS.toUByte())
        ) {
            val t2 = getTime()
            val elapsedTimeMs = getElapsedTimeMs(t1, t2)
            val recvAddress = getAddressStr(recvAddr)
            if (recvAddress != null) {
                return if (recvAddress == destinationStr) {
                    ProbeResult.Done(recvAddress, elapsedTimeMs)
                } else {
                    ProbeResult.SuccessfulHop(recvAddress,elapsedTimeMs)
                }
            }
        } else if (
            (recvIphdr.ip_p == IPPROTO_ICMP.toUByte()) &&
            (recvIcmphdr.icmp_type == ICMP_ECHOREPLY.toUByte()) &&
            (recvIcmphdr.icmp_code == 0.toUByte())
        ) {
            val t2 = getTime()
            val elapsedTimeMs = getElapsedTimeMs(t1, t2)
            val recvAddress = getAddressStr(recvAddr)
            if (recvAddress != null) {
                if (recvAddress == destinationStr) {
                    return ProbeResult.Done(recvAddress, elapsedTimeMs)
                }
            }
        }
        return ProbeResult.Failure("address not found in response")
    }
}

fun traceroute(args: Args) {
    val maxHops = args.maxHops
    val port = interop_htons(args.port.toUShort())
    var currentTtl = args.firstHop
    val address: sockaddr = identifyHost(args.host)?.pointed ?: throw Exception("failed to get an address")
    val targetAddress = getAddressStr(address) ?: run {
        // raise error
        return
    }
    var retries = 0
    while (true) {
        val probeResult = probeHop(
            timeoutMs = args.timeout,
            port = port,
            destination = address,
            destinationStr = targetAddress,
            currentTtl = currentTtl,
            packetSize = args.packetSize
        )
        when (probeResult) {
            is ProbeResult.Failure -> {
                if (retries > 0) {
                    println()
                    retries = 0
                }
                println("failed: ${probeResult.info}")
                return
            }
            is ProbeResult.Done -> {
                if (retries > 0) {
                    println()
                    retries = 0
                }
                println("hop ${currentTtl}, ${probeResult.address}: ${probeResult.time}ms")
                println("done!")
                return
            }
            is ProbeResult.SuccessfulHop -> {
                if (retries > 0) {
                    println()
                    retries = 0
                }
                println("hop ${currentTtl}, ${probeResult.address}: ${probeResult.time}ms")
                currentTtl += 1
            }
            is ProbeResult.Timeout -> {
                if (retries == 0) {
                    print("hop $currentTtl, ")
                }
                if (retries >= args.retries) {
                    println("* timed out")
                    retries = 0
                    currentTtl += 1
                    continue
                }
                print("* ")
                retries += 1
            }

            else -> {
                println("this shouldn't be happening")
            }
        }
        if (currentTtl >= maxHops) {
            println("hit max hops")
            return
        }
    }
}