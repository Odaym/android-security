package com.saltserv.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.Serializable
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import java.security.Signature
import java.util.Enumeration

class DigiSignTrials {
    companion object {
        const val TAG = "DigiSignTrials"
        const val KEY_ALIAS = "keyAlias"
        const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        private fun getKey(): PrivateKeyEntry? {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
            }

            val entry = ks.getEntry(KEY_ALIAS, null)

            if (entry !is PrivateKeyEntry) {
                return null
            }

            return entry
        }

        fun generateKeyPair(): KeyPair {
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE_PROVIDER
            )

            val parameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA512
            ).build()

            kpg.initialize(parameterSpec)

            return kpg.generateKeyPair()
        }

        fun sign(message: ByteArray): ByteArray {
            val key = getKey() ?: throw Exception("Key not found")

            return Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initSign(key.privateKey)
                update(message)
                sign()
            }
        }

        fun verify(message: ByteArray, signature: ByteArray) {
            val key = getKey() ?: throw Exception("Key not found")

            Signature.getInstance(SIGNATURE_ALGORITHM).apply {
                initVerify(key.certificate)
                update(message)
                verify(signature)
                Log.d(TAG, "sign: The document has been verified")
            }
        }

        fun listAllKeys(): Enumeration<String> {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply {
                load(null)
            }

            return ks.aliases()
        }
    }
}