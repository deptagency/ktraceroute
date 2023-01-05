# To-dos:

* clean up allocated memory (I'm particularly thinking of the syscalls that return linked lists of addresses, but there may be others)
* the standard 3-sample packet probe with stats like min, max, avg
* probing over UDP & TCP
* multiplatform support (developed on MacOS, and there's at least one platform specific detail for packet creation I can think of right now)
* network interface handling (it's hardcoded right now)
* to fulfill the original vision of this project: abstract this code into an independent library