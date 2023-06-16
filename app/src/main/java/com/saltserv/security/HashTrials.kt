package com.saltserv.security

import java.security.MessageDigest

class HashTrials {
    companion object {
        const val TAG = "HashTrials"

        fun hashMessage(message: ByteArray): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            return md.digest(message)
        }
    }
}