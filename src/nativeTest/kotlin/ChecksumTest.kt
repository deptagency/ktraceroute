import kotlinx.cinterop.*
import platform.darwin.inet_aton
import platform.posix.*
import kotlin.test.Test
import kotlin.test.assertEquals

class ChecksumTest {
    @Test
    fun testIpChecksum() {
        val dataLen = 4
        val ipLen = IP4_HDRLEN + ICMP_HDRLEN + dataLen
        val ip = getIp(ipLen.toUShort())
        inet_aton("0.0.0.0", ip.pointed.ip_src.ptr).toUInt()
        inet_aton("0.0.0.0", ip.pointed.ip_dst.ptr).toUInt()
        val result: UShort = checksum(ip.reinterpret(), IP4_HDRLEN)
        assertEquals(0x9CBA.toString(16), result.toString(16))
    }

    @Test
    fun testIcmpChecksum() {
        val icmp = getIcmp(0x1234, 0x1)
        val result: UShort = checksum(icmp.reinterpret(), 8)
        assertEquals(0xCAE5.toString(16), result.toString(16))
    }

    @Test
    fun testVerifyChecksum() {
        val icmp = getIcmpWithChecksum(0x1234, 0x1)
        val result: UShort = checksum(icmp.reinterpret(), 8)
        assertEquals(0x0.toString(16), result.toString(16))
    }

    @Test
    fun testVerifyIcmpWithDataChecksum() {
        memScoped {
            val buf = allocArray<uint8_tVar>(8 + 4)
            val icmp = getIcmp(0x1, 0x9)
            memcpy(buf, icmp, 8)
            val data = "TEST".utf8
            memcpy(buf+8, data.ptr, 4)

            val result: UShort = checksum(buf.reinterpret(), 12)
            assertEquals(0x5c50.toString(16), result.toString(16))
        }
    }
}