import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.*
import javax.xml.bind.DatatypeConverter

object Utils {
    fun getOrCreateOutputDir(): File {
        val dir = File(OUTPUT_DIR, UUID.randomUUID().toString())
        dir.mkdirs()
        return dir
    }

    @Throws(Exception::class)
    fun getSHA256(byteArray: ByteArray): ByteArray {
        return getSHA256(ByteArrayInputStream(byteArray))
    }

    @Throws(Exception::class)
    fun getSHA1(byteArray: ByteArray): ByteArray {
        return getSHA1(ByteArrayInputStream(byteArray))
    }

    @Throws(Exception::class)
    fun getSHA256(file: File): ByteArray {
        return getSHA256(FileInputStream(file))
    }

    @Throws(Exception::class)
    fun getSHA256(inputStream: InputStream): ByteArray {
        return getHash(inputStream, "SHA-256")
    }

    @Throws(Exception::class)
    fun getSHA1(inputStream: InputStream): ByteArray {
        return getHash(inputStream, "SHA-1")
    }

    @Throws(Exception::class)
    fun getMD5(inputStream: InputStream): ByteArray {
        return getHash(inputStream, "MD5")
    }

    private fun getHash(inputStream: InputStream, algorithm: String): ByteArray {
        val digest = MessageDigest.getInstance(algorithm)
        var n = 0
        val buffer = ByteArray(8192)
        while (n != -1) {
            n = inputStream.read(buffer)
            if (n > 0) {
                digest.update(buffer, 0, n)
            }
        }
        inputStream.close()
        return digest.digest()
    }

    fun toHex(data: ByteArray): String {
        return DatatypeConverter.printHexBinary(data)
    }

    fun fromHex(string: String): ByteArray {
        return DatatypeConverter.parseHexBinary(string)
    }

    fun toBase64(data: ByteArray): String {
        return Base64.getEncoder().encodeToString(data)
    }

    fun fromBase64(string: String): ByteArray {
        return Base64.getDecoder().decode(string)
    }

    /* copy from java.util.jar.Manifest
    No line may be longer than 72 bytes (not characters), in its UTF8-encoded form.
    If a value would make the initial line longer than this, it should be continued
    on extra lines (each starting with a single SPACE).
     */
    fun make72Safe(line: StringBuffer) {
        var length = line.length
        if (length > 72) {
            var index = 70
            while (index < length - 2) {
                line.insert(index, "\r\n ")
                index += 72
                length += 3
            }
        }
        return
    }

    fun formatEntryForHashing(key: String, hashValue: String): String {
        val buffer1 = StringBuffer()
        buffer1.append("Name: "+key)
        buffer1.append("\r\n")
        Utils.make72Safe(buffer1)

        val buffer2 = StringBuffer()
        buffer2.append("SHA-256-Digest: "+ hashValue)
        buffer2.append("\r\n")
        Utils.make72Safe(buffer2)
        return buffer1.append(buffer2).append("\r\n").toString()
    }
}