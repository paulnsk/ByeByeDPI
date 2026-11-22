package io.github.romanvht.byedpi.core

class ByeDpiProxy {
    companion object {
        init {
            System.loadLibrary("byedpi")
        }
    }

    fun startProxy(args: Array<String>, journalDir: String? = null): Int = jniStartProxy(args, journalDir)

    fun stopProxy(): Int {
        return jniStopProxy()
    }

    private external fun jniStartProxy(args: Array<String>, journalDir: String?): Int
    private external fun jniStopProxy(): Int
}
