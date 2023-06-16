package com.saltserv.security

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets

class MasterKeyTrials {

    companion object {
        private const val SHARED_PREFS_FILE = "my_shared_prefs_file"
        private const val SHARED_PREFS_KEY_BOOLEAN = "key_boolean"
        private const val SECRET_FILE = "mysecretfile.txt"
        const val TAG = "MasterKeyTrials"

        private fun getMasterKey(context: Context) = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        private fun getEncryptedSharedPreferences(context: Context) =
            EncryptedSharedPreferences.create(
                context,
                SHARED_PREFS_FILE,
                getMasterKey(context),
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

        fun writeToSharedPrefs(context: Context) {
            val sharedPrefs = getEncryptedSharedPreferences(context)
            sharedPrefs.edit().apply {
                putBoolean(SHARED_PREFS_KEY_BOOLEAN, false)
                apply()
                Log.d(TAG, "writeToSharedPrefs: Written successfully")
            }
        }

        fun readFromSharedPrefs(context: Context): Boolean {
            val sharedPrefs = getEncryptedSharedPreferences(context)
            return sharedPrefs.getBoolean(SHARED_PREFS_KEY_BOOLEAN, false)
        }

        fun writeFile(context: Context) {
            val fileToWrite = File(context.filesDir, SECRET_FILE)

            val encryptedFile = EncryptedFile.Builder(
                context,
                fileToWrite,
                getMasterKey(context),
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()

            // Cannot exist before using openFileOutput()
            if (fileToWrite.exists()) {
                fileToWrite.delete()
            }

            val fileContent = "MY SUPER-SECRET INFORMATION".toByteArray(Charsets.UTF_8)
            encryptedFile.openFileOutput().apply {
                write(fileContent)
                flush()
                close()
            }
        }

        fun readFile(context: Context): ByteArray {
            val fileToRead = File(context.filesDir, SECRET_FILE)

            val encryptedFile = EncryptedFile.Builder(
                context,
                fileToRead,
                getMasterKey(context),
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()

            val inputStream = encryptedFile.openFileInput()
            val byteArrayOutputStream = ByteArrayOutputStream()
            var nextByte: Int = inputStream.read()

            while (nextByte != -1) {
                byteArrayOutputStream.write(nextByte)
                nextByte = inputStream.read()
            }

            return byteArrayOutputStream.toByteArray()
        }
    }
}

