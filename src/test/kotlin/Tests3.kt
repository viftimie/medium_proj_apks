import junit.framework.Assert
import org.junit.Test
import sun.security.x509.X509CertImpl
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import java.util.jar.Manifest
import java.util.zip.ZipFile
import javax.crypto.Cipher

private const val EXPECTED_FORMATTED_ENTRY_ANDROID_MANIFEST =
    "Name: AndroidManifest.xml\r\nSHA-256-Digest: Mn0EqrCsBqzJcKpag+kBF+521SwCsH8GQZsyftQZ9D4=\r\n\r\n"

class Tests3 {
    @Test
    fun check_certSF_hashing_formula() {
        val pairs = listOf(
            """
            Name: AndroidManifest.xml
            SHA-256-Digest: Mn0EqrCsBqzJcKpag+kBF+521SwCsH8GQZsyftQZ9D4=
            """.trimIndent().trim() to "XU53mmRFSDtfzEAbMy5AsYj85x/hWpV2oV6Nq6WROCg=",

            """
            Name: res/interpolator/btn_checkbox_checked_mtrl_animation_interpolato
             r_0.xml
            SHA-256-Digest: 8sgadJJVD+km1ZdC2CoMDnIDxTrrssQdPBKovDe3gCw=
            """.trimIndent().trim() to "T6K3HJwYzMtHaQD2c0WNjLyLYJg0zGuk8qh+/h8CszE="
        )

        for(pair in pairs) {
            println(pair.first)
            val entryFormatted = pair.first.replace("\n","\r\n")+"\r\n\r\n"
            val sha256Base64Expected = pair.second

            val entryFormattedBytes = entryFormatted.toByteArray()
            val sha256Actual = Utils.getSHA256(entryFormattedBytes)
            val sha256Base64Actual = Utils.toBase64(sha256Actual)
            Assert.assertEquals(sha256Base64Expected, sha256Base64Actual)
        }
    }

    @Test
    fun check_certSF_vs_ManifestMF() {
        val zipFile = ZipFile(TINDER_APK) //of JarFile

        val manifestMfEntry = zipFile.getEntry("META-INF/MANIFEST.MF")
        val manifestMF = Manifest(zipFile.getInputStream(manifestMfEntry))
        val manifestMfEntries = manifestMF.entries.keys.toSet()

        val certSfEntry = zipFile.getEntry("META-INF/CERT.SF")
        val certSF = Manifest(zipFile.getInputStream(certSfEntry))
        val certSFEntries = certSF.entries.keys.toSet()
        Assert.assertEquals(certSFEntries, manifestMfEntries)

        val sha256Base64OfManifestMfExpected = certSF.mainAttributes.getValue("SHA-256-Digest-Manifest")
        val sha256ActualOfManifestMf = Utils.getSHA256(zipFile.getInputStream(manifestMfEntry))
        val sha256Base64OfManifestMfActual = Utils.toBase64(sha256ActualOfManifestMf)
        Assert.assertEquals(sha256Base64OfManifestMfExpected, sha256Base64OfManifestMfActual)

        for(key in manifestMfEntries) {
            val entryFromManifestMF = manifestMF.entries[key]!!
            val entryFromCertSF = certSF.entries[key]!!
            val entryFormatted = Utils.formatEntryForHashing(key, entryFromManifestMF.getValue("SHA-256-Digest"))
            val entryFormattedBytes = entryFormatted.toByteArray()

            val sha256Actual = Utils.getSHA256(entryFormattedBytes)
            val sha256Base64Actual = Utils.toBase64(sha256Actual)
            val sha256Base64Expected = entryFromCertSF.getValue("SHA-256-Digest")

            Assert.assertEquals(sha256Base64Expected, sha256Base64Actual)
            println("Checked: ${key} ")
        }
        println("*** check_certSF_vs_ManifestMF()")
    }

    /*
    I've tested with SHA256, SHA1 & the values just don't match with what I read from CERT.RSA
     */
    @Test
    fun check_certRsa(){
        val zipFile = ZipFile(TINDER_APK) //of JarFile

        val certSfEntry = zipFile.getEntry("META-INF/CERT.SF")
        val certSfBytes = zipFile.getInputStream(certSfEntry).readBytes()

        val sha256CertSF = Utils.getSHA256(certSfBytes)
        val sha256Base64CertSF = Utils.toBase64(sha256CertSF)

        val sha1CertSF = Utils.getSHA1(certSfBytes)
        val sha1Base64CertSF = Utils.toBase64(sha1CertSF)

        val certRsaEntry = zipFile.getEntry("META-INF/CERT.RSA")
        val certRsaInputStream = zipFile.getInputStream(certRsaEntry)
        val certFactory = CertificateFactory.getInstance("X.509")
        val certificate: X509Certificate = certFactory.generateCertificates(certRsaInputStream).first() as X509Certificate

        with(certificate) {
            //or "SHA-256" or "MD5"
            println("fingerprint SHA1: "+ (this as X509CertImpl).getFingerprint("SHA1")) //609823BAED399D9A97138D636550EBE82014CF2E

            println("publicKey.encoded: "+ Arrays.toString(publicKey.encoded)) //294 byte
            println("publicKey.encoded SHA256 + BASE64: "+ Utils.toHex(Utils.getSHA256(publicKey.encoded)))
            println("publicKey.encoded SHA1 + BASE64: "+ Utils.toHex(Utils.getSHA1(publicKey.encoded)))

            val cipher = Cipher.getInstance("RSA")
            cipher.init(Cipher.DECRYPT_MODE, publicKey)
            val result = cipher.doFinal(this.signature)
            //35: 48,33,48,9,6,5,43,14,3,2,26,5,0,4,20,-33,108,-44,-110,18,60,16,-76,-66,-21,-7,-22,-21,34,-77,70,19,-67,52,-72

            println("signature -> DEC.data " + Arrays.toString(result))
        }
        println("*** check1()")
    }
}

/*
Certificate fingerprints:
MD5:  28:DE:25:1A:44:05:DF:91:08:AC:59:C8:CB:7F:32:2C
SHA1: 60:98:23:BA:ED:39:9D:9A:97:13:8D:63:65:50:EB:E8:20:14:CF:2E
SHA256: 8A:B1:4F:D7:50:B8:20:57:4D:20:C3:54:41:EA:14:A9:B5:D1:95:9A:31:04:0C:EC:12:B4:6B:B2:90:F4:DA:1B
Signature algorithm name: SHA1withRSA
Subject Public Key Algorithm: 1024-bit RSA key

SHA256 (CERT.SF) 32: 3,-76,-64,87,-29,107,-51,28,-118,-91,108,102,30,-65,37,41,-48,-54,127,125,106,-115,-94,-28,-61,33,8,-18,25,-78,-75,-96
Base64 String = 44: A7TAV+NrzRyKpWxmHr8lKdDKf31qjaLkwyEI7hmytaA=
44: 65,55,84,65,86,43,78,114,122,82,121,75,112,87,120,109,72,114,56,108,75,100,68,75,102,51,49,113,106,97,76,107,119,121,69,73,55,104,109,121,116,97,65,61

SHA1 (CERT.SF)  20: -104,-87,-47,29,-12,35,-31,-40,114,-63,105,87,-3,16,-34,63,117,8,-52,84
Base64 String = 28: mKnRHfQj4dhywWlX/RDeP3UIzFQ=
28: 109,75,110,82,72,102,81,106,52,100,104,121,119,87,108,88,47,82,68,101,80,51,85,73,122,70,81,61
 */
