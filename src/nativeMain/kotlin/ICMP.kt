import kotlinx.cinterop.*
import platform.posix.*
import sockets.interop_htons
import sockets.interop_ntohs

const val IP4_HDRLEN = 20 // IPv4 header length
const val ICMP_HDRLEN = 8 // ICMP header length for echo request, excludes data

//int status, datalen, sd, *ip_flags;
//const int on = 1;
//char *interface, *target, *src_ip, *dst_ip;
//struct ip iphdr;
//struct icmp icmphdr;
//uint8_t *data, *packet;
//struct addrinfo hints, *res;
//struct sockaddr_in *ipv4, sin;
//struct ifreq ifr;
//void *tmp;

// Allocate memory for various arrays.
//data = allocate_ustrmem (IP_MAXPACKET);
//packet = allocate_ustrmem (IP_MAXPACKET);
//interface = allocate_strmem (40);
//target = allocate_strmem (40);
//src_ip = allocate_strmem (INET_ADDRSTRLEN);
//dst_ip = allocate_strmem (INET_ADDRSTRLEN);
//ip_flags = allocate_intmem (4);

fun checksum(data: CPointer<uint8_tVar>, len: Int): UShort {
    var acc: uint32_t = 0xffff.toUInt()
    for (i in 0 until len step 2) {
        memScoped {
            val word: uint16_tVar = alloc()
            memcpy(word.ptr, data+i, 2)
            acc += interop_ntohs(word.value)
            if (acc > 0xffff.toUInt()) {
                acc -= 0xffff.toUInt()
            }
        }
    }
    if ((len and 0b1) == 1) {
        memScoped {
            val word: uint16_tVar = alloc()
            memcpy(word.ptr, data+(len-1), 1)
            acc += interop_ntohs(word.value)
            if (acc > 0xffff.toUInt()) {
                acc -= 0xffff.toUInt()
            }
        }
    }
    return interop_htons(acc.inv().toUShort());
}

fun getIp(ipLen: uint16_t): CPointer<ip> {
    val ip = nativeHeap.alloc<ip>()
    ip.ip_v = 4u
    ip.ip_hl = 5u // defined as header length in units of 32-byte words (minimum size is 5,
                  // only increases if there's options)
    ip.ip_tos = 0u
    ip.ip_len = interop_htons(ipLen) // defined as packet length (header + data) in units of bytes
    ip.ip_id = interop_htons(321)
    ip.ip_off = interop_htons(0)
    ip.ip_ttl = 64u
    ip.ip_p = IPPROTO_ICMP.toUByte()
    ip.ip_sum = 0u
    return ip.ptr
}

fun getIcmp(id: Int, seq: Int): CPointer<icmp> {
    val icmp = nativeHeap.alloc<icmp>()
    icmp.icmp_type = ICMP_ECHO.toUByte()
    icmp.icmp_code = 0u
    icmp.icmp_hun.ih_idseq.icd_id = interop_htons(id.toUShort())
    icmp.icmp_hun.ih_idseq.icd_seq = interop_htons(seq.toUShort())
    icmp.icmp_cksum = 0u
    return icmp.ptr
}

fun getIcmpWithChecksum(id: Int, seq: Int): CPointer<icmp> {
    val icmp = getIcmp(id, seq)
    icmp.pointed.icmp_cksum = checksum(icmp.reinterpret(), ICMP_HDRLEN)
    return icmp
}