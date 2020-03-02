import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

class Tests1 {
    @Test
    fun list_all_entries_in_apk() {
        val zipFile = ZipFile(TINDER_APK)//or JarFile

        val entries = zipFile.entries()
        var ze: ZipEntry? //or JarEntry
        while (entries.hasMoreElements()) {
            ze = entries.nextElement()
            println(ze.name)
        }
        zipFile.close()
        println("*** DONE: list_all_entries_in_apk()")
    }

    @Test
    fun unzip() {
        val zipFile = ZipFile(TINDER_APK) //or JarFile
        val outputDir = Utils.getOrCreateOutputDir()

        val entries = zipFile.entries()
        var ze: ZipEntry?
        while (entries.hasMoreElements()) {
            ze = entries.nextElement()
            if(ze.isDirectory)
                continue

            val outputFile = File(outputDir, ze.name)
            outputFile.parentFile.mkdirs()
            val inputStream: InputStream = zipFile.getInputStream(ze)
            val fos = FileOutputStream(outputFile)
            inputStream.copyTo(fos)

            fos.close()
            inputStream.close()
        }
        zipFile.close()
        println("*** DONE: unzip() $outputDir")
    }
}