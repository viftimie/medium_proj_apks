import junit.framework.Assert
import org.junit.Test
import java.io.File
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.Manifest
import java.util.zip.ZipFile

class Tests2 {
    /*
    - We parse MANIFEST.MF
    - We get the entry corresponding for AndroidManifest.xml
    In the actual file, this is the entry:
    Name: AndroidManifest.xml
    SHA-256-Digest: Mn0EqrCsBqzJcKpag+kBF+521SwCsH8GQZsyftQZ9D4=
    - we read from the entry the "SHA-256-Digest" attribute. This is in Base64, if you decode it you get a ByteArray inside is the hash
    This ByteArray is the hash (SHA256 in this case) for "AndroidManifest.xml"
    - To confirm, we get the entry for "AndroidManifest.xml" & open the stream & calculate the hash
     */
    @Test
    fun checkEntry_AndroidManifest() {
        val targetEntryName = "AndroidManifest.xml"

        val file = File(TINDER_APK)
        val jarFile = JarFile(file)

        val manifestEntry = jarFile.getEntry("META-INF/MANIFEST.MF") as JarEntry
        val manifest = Manifest(jarFile.getInputStream(manifestEntry))
        val sha256Base64Expected = manifest.entries[targetEntryName]!!.getValue("SHA-256-Digest")

        val entry = jarFile.getEntry(targetEntryName) as JarEntry
        val inputStream = jarFile.getInputStream(entry)
        val sha256Actual: ByteArray = Utils.getSHA256(inputStream)
        val sha256Base64Actual: String = Utils.toBase64(sha256Actual)

        Assert.assertEquals(sha256Base64Expected, sha256Base64Actual)
        println("*** DONE: checkEntry_AndroidManifest()")
    }

    /*
    For each entry in the MANIFEST.MF we compare the hash value ("SHA-256-Digest")
    with the one calculated on the content of the actual file
    We don't need to unzip the APK, we can get the content of the entry via zipFile.getInputStream(entry)
     */
    @Test
    fun check_manifestMf_hashes() {
        val file = File(TINDER_APK)
        val zipFile = ZipFile(file)//or JarFile

        val manifestEntry = zipFile.getEntry("META-INF/MANIFEST.MF")
        val manifest = Manifest(zipFile.getInputStream(manifestEntry))

        manifest.entries.forEach {
            val entry = zipFile.getEntry(it.key)
            val sha256Base64Expected = it.value.getValue("SHA-256-Digest")

            val inputStream = zipFile.getInputStream(entry)
            val sha256Actual: ByteArray = Utils.getSHA256(inputStream)
            val sha256Base64Actual: String = Utils.toBase64(sha256Actual)

            Assert.assertEquals(sha256Base64Expected, sha256Base64Actual)
            println("Checked: ${it.key} ")
        }
        zipFile.close()
        println("*** DONE: check_manifestMf_hashes()")
    }

    /*
    Basically the 2 files: MANIFEST.MF + CERT.SF should have all files from APK (except MANIFEST.MF, CERT.RSA, CERT.SF)
     */
    @Test
    fun check_entries_manifestMf_vs_certSf_vs_APK() {
        val file = File(TINDER_APK)
        val zipFile = ZipFile(file)

        val shouldNotBeInManifestMF = listOf(
            "META-INF/MANIFEST.MF",
            "META-INF/CERT.RSA",
            "META-INF/CERT.SF"
        )

        val allZipEntries = zipFile.entries().toList().map { it.name }
        val zipEntriesOfInterest = allZipEntries.filter { it !in shouldNotBeInManifestMF }.toSet()

        val manifestMfEntry = zipFile.getEntry("META-INF/MANIFEST.MF")
        val manifestMF = Manifest(zipFile.getInputStream(manifestMfEntry))
        val manifestMfEntries = manifestMF.entries.keys.toSet()

        val certSfEntry = zipFile.getEntry("META-INF/CERT.SF")
        val certSF = Manifest(zipFile.getInputStream(certSfEntry))
        val certSFEntries = certSF.entries.keys.toSet()

        Assert.assertEquals(zipEntriesOfInterest, manifestMfEntries)
        Assert.assertEquals(certSFEntries, manifestMfEntries)
        println("*** check_entries_manifestMf_vs_certSf_vs_APK()")
    }
}