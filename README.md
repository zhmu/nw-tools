### NLM tools

## nlm2elf

This tool can convert a NetWare Loadable Module file to an ELF file. This ELF file can in turn be analysed in tools like IDA or Ghidra.

Packed NLM files, such as `SERVER.NLM` embedded in `SERVER.EXE`, are supported. `extract-loader-nlm` can be use to extract it from `SERVER.EXE`.

The code is a mess.

## extract-loader-nlm

Given a `SERVER.EXE`, this will extract the embedded `SERVER.NLM` therein. It uses the same heuristics as the loader patching utility `LSWAP.EXE`. The resulting `SERVER.NLM` can be used by `nlm2elf` to generate an ELf file for further analysis.

## extract-loader-symbols

Given a memory dump of an active `SERVER.EXE`, this will write a text file with the names and offsets of all symbols present in the loader. This is very useful when analyzing the embedded NLM.

The offset is hardcoded for my copy of NetWare 3.12, which contains the Y2K-patched loader. You may need to alter the offset for your specific loader version.

## extract-server-symbols

Given a ELF file of `SERVER.NLM` (which can be extracted using `extrace-loader-nlm` and converted using `nlm2elf`), this utility writes a text file containing all symbols with the respective offsets present.

## dump-bindery

This tool will decode the NetWare 3.x bindery. It must be invoked with paths to `net$obj.sys`, `net$prop.sys` and `net$val.sys`, which it will process and output a text-based representation of the contents thereof.

When NetWare is running, these files will be inaccessible. I tend to use my `nwfs386` shell tool to extract these files directly from a disk image. Alternatively, there are various tools available to lock/unlock the bindery which will grant you access to these files.

## nw-crypt

C-code illustrating how NetWare 3.x password hashing and client logins are implemented. Refer to [my blog post](https://blog.rink.nu/2023/02/03/on-netware-3.x-password-hashing/) for more information.

This code is specificially licensed using Creative Commons CC BY. All other code in this repository is licensed using GPLv3.
