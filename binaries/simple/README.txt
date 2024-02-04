Simple Binary

This folder contains the build files for a simple executable, that performs a
few indirect calls, prints "Hello, World!" and calls SYS_exit with a status of
code of zero.

Additionally, this program is built with what might seem like a fairly strange,
or perhaps seemingly unneeded, linker script. The reason for its existence is
that we want the environment in which our simple example runs to be predictable,
consistent, and for information about it to be easily interpretable from a
glance at an address.
