<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## SHELLTER Unpacker by Elastic Security Labs

Elastic Security Labs is releasing a dynamic unpacker for binaries protected by SHELLTER. This tool leverages a combination of dynamic and static analysis techniques to automatically extract multiple payload stages from a SHELLTER-protected binary.

As SHELLTER offers a wide range of optional features, this unpacker is not fully comprehensive, although it does successfully process a large majority of tested samples. Even with unsupported binaries, it is typically able to extract at least one payload stage.

**For safety reasons, this tool should only be executed within an isolated virtual machine.** During the unpacking process, potentially malicious executable code is mapped into memory. Although some basic safeguards have been implemented, they are not infallible.

SHELLTER research is published here:

- https://www.elastic.co/security-labs/taking-shellter

## Author
-   [`x86matthew`](https://x.com/x86matthew)

## Description

| Path               | Description                             |
| ------------------ | --------------------------------------- |
| [`ShellterUnpacker.cpp`](ShellterUnpacker.cpp)    | SHELLTER Unpacker Source |
| [`ShellterUnpacker.bin`](ShellterUnpacker.bin)    | SHELLTER Portable Executable (PE-EXE) |

## Requirements

- Windows OS (Virtual Machine)

## ShellterUnpacker.bin

### Usage

Extracts out multiple payload stages from a SHELLTER-protected binary. Output also includes:
- License expiry date
- Self-disarm date
- Infection start date
- AES key
- AES IV

```
Usage: ShellterUnpacker.exe <input_exe>

ShellterUnpacker.exe C:\tmp\FilelistCreator.exe

Shellter Payload Extractor
 - Elastic Security Labs

Warning: This tool maps potentially malicious code into memory. This should only be run within a VM.
Type "confirm" to continue: confirm

Starting...
Extracting stage1...
Launching process...
Setting breakpoint...
Resuming process...
Waiting for exception, this may take a few seconds...
Caught breakpoint
Extracting code...
Writing dump to FilelistCreator.exe.stage1...
Extracting stage2...
Extracting dates...
License expiry date  : 2026-04-17 19:17:24.055000
Self-disarm date     : 2026-04-27 22:40:00.954060
Infection start date : 2025-04-27 22:40:00.954060
Writing dump to FilelistCreator.exe.stage2_encrypted...
Stage2 payload size  : 496128 bytes
Stage2 AES key       : B316485AC5E717C96BBB79253B3BDEE9
Stage2 AES IV        : 922F38248E21DB4665D8C2C4DE513C14
Decrypting...
Writing dump to FilelistCreator.exe.stage2_decrypted...
Decompressed successfully
Writing dump to FilelistCreator.exe.stage2_decrypted_and_decompressed...
Finished
```



