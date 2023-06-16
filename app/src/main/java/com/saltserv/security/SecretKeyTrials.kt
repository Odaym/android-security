package com.saltserv.security

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class SecretKeyTrials {

    companion object {
        private val key = KeyGenerator.getInstance("AES").generateKey()
        private val iv = "aabbccddeeffgghh".toByteArray()
        val TAG = "SECRETKEYTRIALS"

        fun encryptMessage(message: ByteArray): ByteArray =
            getCipher(CipherMode.ENCRYPT).doFinal(message)

        fun decryptMessage(message: ByteArray): ByteArray =
            getCipher(CipherMode.DECRYPT).doFinal(message)

        private fun getCipher(cipherMode: CipherMode): Cipher {
            val cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING")
            cipher.init(cipherMode.mode, key, IvParameterSpec(iv))
            return cipher
        }

        enum class CipherMode(val mode: Int) {
            ENCRYPT(Cipher.ENCRYPT_MODE),
            DECRYPT(Cipher.DECRYPT_MODE)
        }
    }
}