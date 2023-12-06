<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## GULOADER malware analysis tools by Elastic Security Labs

Elastic Security Labs wrote IDAPython script used to fix control flow graph (CFG) using TinyTracer log file. The Python script will modify exceptions with short jumps based on the EIP modification inside GuLoader. This algorithm and XOR key changes between samples. The script can be run using "Script Command" feature in IDA Pro, a prompt will ask for the TinyTracer log file. In order to verify it was succesfully applied, review the command output and check the "Patched bytes" section within IDA Pro.

GULOADER research is published here:

- https://www.elastic.co/security-labs/getting-gooey-with-guloader-downloader

## Description

| Path               | Description                             |
| ------------------ | --------------------------------------- |
| [`guloader_FixCFG.py`](guloader_FixCFG.py)    | Fixes CFG by removing VEH using TinyTracer log file |

## Requirements

### Python

- Python3 `>=3.10`
