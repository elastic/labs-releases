<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## BLISTER malware analysis tools by Elastic Security Labs

BLISTER is a loader discovered by Elastic in December 2021. It is actively being used to load a variety of malware including clipbankers, information stealers, trojans, ransomware, and shellcode.

The configuration extractor was originally published in December of 2021 and updated in August of 2023.

BLISTER research is published here:

- https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign
- https://www.elastic.co/security-labs/revisiting-blister-new-developments-of-the-blister-loader#payload-extractor-update

## Description

| Path               | Description                             |
| ------------------ | --------------------------------------- |
| [`blister_payload_extractor.py`](blister_payload_extractor.py)    | Decrypt BLISTER payload with configuration |

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

## blister_payload_extractor.py

Extracts payload and configuration from BLISTER loader.

### Usage

```text
(venv) $$> python blister_payload_extractor.py -h
usage: Blister config file extractor [-h] (-f FILE | -d DIRECTORY) -o OUTDIR

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Blister file path
  -d DIRECTORY, --directory DIRECTORY
                        Blister directory
  -o OUTDIR, --outdir OUTDIR
                        Blister output directory
```
