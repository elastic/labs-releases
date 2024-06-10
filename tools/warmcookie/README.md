<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## WARMCOOKIE malware analysis tools by Elastic Security Labs

Elastic Security Labs wrote IDAPython script used to decrypt strings from WARMCOOKIE. The decrypted strings will be placed in decompiler helping analyst identify key functionality.

WARMCOOKIE research is published here:

- https://www.elastic.co/security-labs/dipping-into-danger

## Description

| Path               | Description                             |
| ------------------ | --------------------------------------- |
| [`warmcookie_str_decrypt.py`](warmcookie_str_decrypt.py)    | Annotates IDA Pro IDB with decrypted strings in decompiler |

## Requirements

### Python

- Python3 `>=3.10`
