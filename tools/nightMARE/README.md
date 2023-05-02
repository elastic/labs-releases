<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## Elastic Security Labs - nightMARE

This directory contains the night**MARE** (Malware Analysis & Reverse Engineering) framework. nightMARE will be a central framework that will allow for an efficient and logical approach to configuration extractors for multiple malware families. 

Previously we'd been building malware configuration extractors to run inside Docker containers, but while this removed some dependency hurdles, it became cumbersome and made automation difficult. While we have another directory in this repository for configuration extractors, we'll be moving them here.

Unveiling of nightMARE - https://www.elastic.co/security-labs/unpacking-icedid

| Module | Description |
| ------ | ----------- |
| [`icedid`](icedid/) | Extractor for the ICEDID malware family |

To run nightMARE, you'll need Python 3.10+ and the dependent libraries in the `requirements.txt` file in the respective directory:

```
python -m pip install ./nightMARE
```

Once you have the requirements installed, you'll run the extractor against an individual binary or a directory containing multiple samples.

## Example Usage

```
$ python nightMARE -h

usage: 

options:
```

## Legacy extractors

If you're looking for our legacy extractors written as Docker containers, you can still find them [here](https://www.elastic.co/security-labs/tools).
