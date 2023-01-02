import kotlinx.cinterop.get
import kotlinx.cinterop.reinterpret
import platform.posix.uint8_tVar
import kotlin.test.Test
import kotlin.test.assertEquals

class ICMPTest {
    private fun byteArrayOf(vararg elements: Int): ByteArray {
        return elements.map { it.toByte() }.toByteArray()
    }

    @Test
    fun testIcmp() {
        val result = getIcmpWithChecksum(0x1234, 0x1)
        val arr: ByteArray = byteArrayOf(0x8, 0x0, 0xe5, 0xca, 0x12, 0x34, 0x0, 0x1)
        var expectedFormatted = ""
        var actualFormatted = ""
        for (i in 0..7) {
            expectedFormatted += arr[i].toUByte().toString(16)
            actualFormatted += result.reinterpret<uint8_tVar>()[i].toUInt().toString(16)
        }
        assertEquals(expectedFormatted, actualFormatted)
    }
}