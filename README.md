# Function Pointer Tracker
This is a proof-of-concept for tracking calls made through function pointers.

The main executable in this repository, `fnptr-poc`, uses `ptrace(2)` to
analyze and control the behavior of an inferior process, in order to locate and
instrument function pointer calls. What exactly constitutes a function pointer
call is still an open question that I hope to use this project to help narrow
down.

The bulk of the interesting code lives under `src/`, but some additional
programs, used for controlled testing of the behavior of the main program,
can be found under `binaries/`.

## Purpose and Limitations
The code inside this repository isn't particularly pretty or well-explained, but
that should be fine seeing as its main goal is to serve primarily for research.
Specifically, the code in this repo is intended to answer the following
questions:
- [X] Is tracking calls made through function pointers possible? (Yes)
- [ ] Can it be done to a wide range of existing applications?
- [ ] Can it be done in a memory- and time-efficient way?

Additionally, this tracker is limited to `x86-64`. It was chosen because it's
the architecture where the barrier to hot modifying and analyzing code is the
lowest. This might change in the future if I decide I want to test the
viability of the techniques used here in architectures like `aarch64`.