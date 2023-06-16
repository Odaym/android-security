package com.saltserv.security

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val message = HashTrials.hashMessage("Hello World".toByteArray())

        Log.d(HashTrials.TAG, "onCreate: ${message.joinToString("") { "%02x".format(it) }}")

        val keyAliases = DigiSignTrials.listAllKeys()
        while (keyAliases.hasMoreElements()) {
            Log.d(DigiSignTrials.TAG, "onCreate: ${keyAliases.nextElement()}")
        }
    }
}