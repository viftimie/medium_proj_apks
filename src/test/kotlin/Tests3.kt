import junit.framework.Assert
import org.junit.Test
import sun.security.pkcs.PKCS7
import sun.security.x509.AlgorithmId
import sun.security.x509.X509CertImpl
import java.security.KeyPairGenerator
import java.security.Signature
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

    @Test
    fun check_certRsa(){
        val zipFile = ZipFile(TINDER_APK) //or JarFile

        val certSfEntry = zipFile.getEntry("META-INF/CERT.SF")
        val certSfBytes = zipFile.getInputStream(certSfEntry).readBytes()

        val certRsaEntry = zipFile.getEntry("META-INF/CERT.RSA")

        val sigBlock: PKCS7 = PKCS7(zipFile.getInputStream(certRsaEntry).readBytes())
        val certificate: X509Certificate = sigBlock.certificates[0]
        val encryptedDigest = sigBlock.signerInfos[0].encryptedDigest
        val algorithmName = AlgorithmId.makeSigAlg("SHA256", "RSA")
        val signature = Signature.getInstance(algorithmName)
        signature.initVerify(certificate.publicKey)
        signature.update(certSfBytes)
        val verify = signature.verify(encryptedDigest)

        Assert.assertEquals(true, verify)
        println("*** check_certRsa()")
    }
}