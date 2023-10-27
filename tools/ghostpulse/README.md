<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## GHOSTPULSE malware analysis tools by Elastic Security Labs

Elastic Security Labs has observed a campaign to compromise users with signed MSIX application packages to gain initial access. The campaign leverages a stealthy loader we call GHOSTPULSE which decrypts and injects its final payload to evade detection.

The extractor takes as input the encrypted file shipped with GHOSTPULSE which contains it's different stages and the final payload.

GHOSTPULSE research is published here:

- https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks

## Description

| Path               | Description                             |
| ------------------ | --------------------------------------- |
| [`ghostpulse_payload_extractor.py`](ghostpulse_payload_extractor.py)    | Extracts payload from encrypted ghostpulse file |

## Requirements

### Python

- Python3 `>=3.10`
- The [nightMARE](../../nightMARE/) library

## Install

```text
$$> virtualenv venv
$$> ./venv/script/activate
(venv) $$> pip install <path-to-esl-repository>/nightMARE
```

## ghostpulse_payload_extractor.py

Extracts payload and configuration from GHOSTPULSE loader.

### Usage

```text
(venv) $$> python ghostpulse_payload_extractor.py -h
usage: GHOSTPULSE payload extractor [-h] (-f FILE | -d DIRECTORY) -o OUTDIR

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  GHOSTPULSE encrypted file path
  -d DIRECTORY, --directory DIRECTORY
                        GHOSTPULSE directory
  -o OUTDIR, --outdir OUTDIR
                        GHOSTPULSE output directory

```
