# ktraceroute

`traceroute` written in Kotlin!

## Background

What started out as a stab at Kotlin/Native library development, turned into a deep-dive effort to rewrite `traceroute` in Kotlin using its wonderful [`cinterop`](https://kotlinlang.org/docs/native-c-interop.html) capability.

This married together a bunch of different areas: Kotlin, C, syscalls & the OS kernel, network programming & TCP/IP.

It's not clear this project is useful in and of itself - there's several (if not many) implementations of `traceroute` already. But it does seem to have yielded some, hopefully, useful examples of pushing Kotlin/Native (and `cinterop`) to its limits. The Kotlin docs are great, but somewhat unclear for parts like memory management, casting, and other minutiae. There should be some good snippets from this project of how to work with those trickier parts of Kotlin/Native.

There's still quite a bit of room for improvement, a short list:
* the standard 3-sample packet probe
* probing over UDP & TCP
* multiplatform support (developed on MacOS, and there's at least one platform specific detail for packet creation I can think of right now)
* network interface handling (it's hardcoded right now)
* and to fulfill the original vision of this project: abstract this code into an independent library