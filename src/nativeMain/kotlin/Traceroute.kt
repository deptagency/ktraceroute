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
            val ifaAddr = addrsIt.pointed!!.ifa_addr?.pointed
            val saFamily = ifaAddr?.sa_family?.toInt()
            val ifaName = addrsIt.pointed!!.ifa_name?.toKString()
            println("ifaName:$ifaName")
            if (name == ifaName) {
                when (saFamily) {
                    AF_INET -> {
                        println("found an interface")
                        return ifaAddr.reinterpret()
                    }
                }
            }
            addrsIt = addrsIt.pointed.ifa_next
        }
        println("none found")
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
//        if (res != null) {
//
////                ?.let { getAddress(it.pointed) }
////            if (address != null) {
////                return address
////            }
//        }
//        return null
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

fun checkRoot() {
    if (getuid() != 0u) {
        println("This program must be run with root to use raw sockets.")
    }
}

fun getInAddr(addr: sockaddr): in_addr? {
    return when (addr.sa_family.toInt()) {
        AF_INET -> {
//            val s = ByteArray([INET_ADDRSTRLEN)
            val saIn = addr.reinterpret<sockaddr_in>()
            println("reinterpreting sin")
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
    data class SuccessfulHop(val address: String, val time: ULong): ProbeResult()
    data class Done(val address: String, val time: ULong): ProbeResult()
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

//        val timeval = alloc<timeval>()
//        with (timeval) {
//            this.tv_sec = 0
//            this.tv_usec = timeoutMs * 1000
//        }
//        setsockopt(recvSocket, SOL_SOCKET, SO_RCVTIMEO, timeval.ptr, sizeOf<timeval>().convert())

//        sendto (sd, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)
        // Send a single null byte UDP packet
        val data = "TEST".utf8
        val bufferSize = IP4_HDRLEN + ICMP_HDRLEN + data.size
        val sendBuf = nativeHeap.allocArray<ByteVar>(bufferSize)
        println("getting icmp packet")
        val icmp = getIcmp(0x1, 0x9)

//        val srcName = ByteArray(256)
//        println("getting hostname")
//        val hnResult = gethostname(srcName.refTo(0).getPointer(this), srcName.size.convert())
//        if (hnResult == -1) {
//            println("failed to get hostname")
//        }
//        val srcNameStr = srcName.decodeToString()
        val ipLen = sizeOf<ip>().shr(2).toUShort()
        val ip = getIp(ipLen)
        // set src addr
//        val srcAddrResult = inet_aton(srcNameStr, ip.pointed.ip_src.ptr)
//        if (srcAddrResult == 0) {
//            return ProbeResult.Failure("source addr $srcNameStr is invalid")
//        }
        val srcAddr = getInterfaceSockaddr("en0")
        // set dest addr
        val destAddr = getInAddr(destination) ?: run {
            return ProbeResult.Failure("") // todo: write error string
        }

        ip.pointed.ip_dst.s_addr = destAddr.s_addr
        ip.pointed.ip_src.s_addr = srcAddr!!.sin_addr.s_addr
        println("hmm")
        println(ip.pointed.ip_src.s_addr)
        // set checksum
        ip.pointed.ip_sum = checksum(ip.reinterpret(), IP4_HDRLEN)
        memcpy(sendBuf, ip, IP4_HDRLEN.toULong())
        memcpy(sendBuf+IP4_HDRLEN, icmp, ICMP_HDRLEN.toULong())
        memcpy(sendBuf+IP4_HDRLEN+ICMP_HDRLEN, data.ptr, data.size.toULong())
        icmp.pointed.icmp_cksum = checksum((sendBuf+IP4_HDRLEN)!!.reinterpret(), ICMP_HDRLEN + data.size)
        memcpy(sendBuf+IP4_HDRLEN, icmp, ICMP_HDRLEN.toULong())

        // Submit request for a raw socket descriptor.
        val sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
        println("sd: $sd")
        if (sd < 0) {
            return ProbeResult.Failure("failed to get outbound socket descriptor")
        }
//        val bindResult = bind(sd, destination.ptr, sizeOf<socklen_tVar>().convert())
//        if (bindResult < 0) {
//            return ProbeResult.Failure("failed to bind send socket")
//        } else {
//            println("bound sending socket")
//        }

// if we're going to use sendto, we don't need to connect...either connect & send _or_ sendto

//        val connectResult = connect(sd, destination.ptr, destination.sa_len.toUInt())
//        if (connectResult < 0) {
//            return ProbeResult.Failure("failed to connect, errno:${strerror(getErrno())?.toKString()}")
//        }

//        println("hdrincl so reached")
//        // turns on option to include IPv4 header
        val soResult = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, cValuesOf(1), sizeOf<IntVar>().convert())
        if (soResult < 0) {
            println()
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
        // send packet
        inet_ntoa(destination.reinterpret<in_addr>().readValue())?.let { println(it.toKString()) }
        val error = sendto(sd, sendBuf, ip.pointed.ip_len.toULong(), 0, destination.ptr, sizeOf<sockaddr>().convert())
        if (error < 0L) {
            return ProbeResult.Failure("error sending packet: ${strerror(getErrno())?.toKString()}")
        }

        // wait for response
        val timeval = alloc<timeval>()
        timeval.tv_sec = 5
        timeval.tv_usec = 0
        val fdSet = alloc<fd_set>()
        posix_FD_ZERO(fdSet.ptr)
        posix_FD_SET(recvSocket, fdSet.ptr)
        fcntl(recvSocket, F_SETFL, O_NONBLOCK)
        println("select reached")
        val retval = select(sd+1, fdSet.ptr, null, null, timeval.ptr);
        if (retval == -1) {
            return ProbeResult.Failure("failed to receive response")
        }
//        } else if (retval == 0) {
//            return ProbeResult.Timeout("receiving response timed out")
//        }
        val buf = ByteArray(IP_MAXPACKET)
        val recvAddr = alloc<sockaddr>()
        println("recvfrom reached")
        val recvSocklen: socklen_t = sizeOf<sockaddr>().convert()
        val bytes = recvfrom(recvSocket, buf.refTo(0), buf.size.toULong(),0, recvAddr.ptr, cValuesOf(recvSocklen))
        println("msg:${buf.toKString()}")
        println("# of bytes:${bytes}")
        close(recvSocket)
        close(sd)
        if (bytes == -1L) {
            val errno = getErrno()
            if (errno == 35) {
                return ProbeResult.Timeout("timed out")
            }
            return ProbeResult.Failure("error receiving packet, errno:$errno")
        } else {
            val recvIphdr = buf.refTo(0).getPointer(this).reinterpret<ip>().pointed
            val recvIcmphdr = buf.refTo(IP4_HDRLEN).getPointer(this).reinterpret<icmp>().pointed
            if (
                (recvIphdr.ip_p == IPPROTO_ICMP.toUByte()) &&
                (recvIcmphdr.icmp_type == ICMP_ECHOREPLY.toUByte()) &&
                (recvIcmphdr.icmp_code == 0.toUByte())
            ) {
                println("woohoo")
//
//                // Stop timer and calculate how long it took to get a reply.
//                (void) gettimeofday (&t2, &tz);
//                dt = (double) (t2.tv_sec - t1.tv_sec) * 1000.0 + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;
//
//                // Extract source IP address from received ethernet frame.
//                if (inet_ntop (AF_INET, &(recv_iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL) {
//                status = errno;
//                fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
//                exit (EXIT_FAILURE);
//            }

//                // Report source IPv4 address and time for reply.
//                printf ("%s  %g ms (%i bytes received)\n", rec_ip, dt, bytes);
//                done = 1;
//                break;  // Break out of Receive loop.
//            }  // End if IP ethernet frame carrying ICMP_ECHOREPLY
            }
        }
        val recvAddress = getAddressStr(recvAddr)
        if (recvAddress != null) {
            println("received addr:${recvAddress}")
            return if (recvAddress == destinationStr) {
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
    val address: sockaddr = identifyHost(args.host)?.pointed ?: throw Exception("failed to get an address")
    val targetAddress = getAddressStr(address) ?: run {
        // raise error
        return
    }
    println("address: $targetAddress, port: ${args.port}")
    var retries = 0
    while (true) {
        println("currentTtl:$currentTtl")
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
                    println("timed out")
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