<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## RedLine Stealer configuration extractor by Elastic Security Labs

## Description

| Path               | Description                             |
| ------------------ | --------------------------------------- |
| [redlinestealer_config_extractor.py](redlinestealer_config_extractor.py)    | Extracts configuration from a RedLine Stealer sample |

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

### Usage

```text
(venv) $$> python redlinestealer_config_extractor.py -h
usage: RedLine Stealer configuration extractor [-h] (-f FILE | -d DIRECTORY) -o
                                              OUTFILE

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  file
  -d DIRECTORY, --directory DIRECTORY
                        directory
  -o OUTFILE, --outfile OUTFILE

```
