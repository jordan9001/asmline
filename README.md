# asmline
interactive assembly / disassembly /  emulation

---

This tool is a very small wrapper around the [Capstone][1], [Keystone][2], and [Unicorn][3] Engines for quickly testing some assembly.

It is a small commandline application for quickly turning bytes to assembly, assembly to bytes, or emulating a small piece of assembly. I often use it as a quick reference/tester when reverse engineering.

A similar tool is rasm2 provided with [radare2][4]

[1]: https://github.com/aquynh/capstone
[2]: https://github.com/keystone-engine/keystone
[3]: https://github.com/unicorn-engine/unicorn
[4]: https://github.com/radareorg/radare2


### Dependencies
The python3 libraries for capstone and keystone-engine must be installed. The python3 library for unicorn should be installed if you want the emulation mode.
```
pip3 install capstone keystone-engine unicorn
```
