<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## ICEDID malware analysis tools by Elastic Security Labs

ICEDID is a malware family discovered in 2017 by IBM X-force researchers and is associated with the theft of login credentials, banking information, and other personal information. ICEDID has been linked to the distribution of several distinct malware families including DarkVNC and COBALT STRIKE.

ICEDID is known to pack its payloads using custom file formats and a custom encryption scheme. Elastic Security Labs is releasing a set of tools to automate the unpacking process and help analysts and the community respond to ICEDID.

A tutorial is available here: <https://www.elastic.co/security-labs/unpacking-icedid>

## Description

| Path               | Description                             | OS compatibility                |
| ------------------ | --------------------------------------- | ------------------------------- |
| decrypt_file.py    | Decrypt ICEDID encrypted file           | Windows and others (not tested) |
| decompress_file.py | Decompress ICEDID compressed file       | Windows only                    |
| rebuild_pe.py      | Rebuild PE from ICEDID custom PE format | Windows and others (not tested) |


| Path                                       | Description                                              | OS compatibility                |
| ------------------------------------------ | -------------------------------------------------------- | ------------------------------- |
| gzip-variant/extract_gzip.py               | Extract binaries from ICEDID fake GZip file              | Windows and others (not tested) |
| gzip-variant/extract_payloads_from_core.py | Extract payloads from the **rebuilt** ICEDID core binary | Windows and others (not tested) |
| gzip-variant/load_core.py                  | Natively Load and execute core **custom PE** binary      | Windows only                    |
| gzip-variant/rebuild_pe.py                 | Rebuild a PE from ICEDID custom PE file                  | Windows and others (not tested) |


## Requirements

### OS

- Windows is required for the following scripts(Tested on Windows 10 22H2)
  - `decompress_file.py`
  - `gzip-variant/load_core.py`

### Python

- Python3 `>=3.10`
- The [nightMARE](../../nightMARE/) library

## Install

```text
$$> virtualenv venv
$$> ./venv/script/activate
(venv) $$> pip install <path-to-esl-repository>/nightMARE
```

## decompress_file.py

Decompress ICEDID's compressed data using Windows LZNT1 decompression algorithm.

### Usage

```text
(venv) $$> python decompress_file.py -h
usage: decompress_file.py [-h] input output

positional arguments:
  input       Input file
  output      Output file

options:
  -h, --help  show this help message and exit
```

## decrypt_file.py

Decrypt ICEDID's encrypted data using their custom algorithm.

### Usage

```text
(venv) $$> python decrypt_file.py -h   
usage: decrypt_file.py [-h] input output     

positional arguments:
  input       Input file
  output      Output file

options:
  -h, --help  show this help message and exit
```

## rebuild_pe.py

Rebuild a PE from ICEDID's custom PE format. 

### Usage

```text
usage: rebuild_pe.py [-h] [-o OFFSET] input output

positional arguments:
  input                 Input file
  output                Output reconstructed PE

options:
  -h, --help            show this help message and exit
  -o OFFSET, --offset OFFSET
                        Offset to real data, skip possible garbage
```



## gzip-variant/extract_gzip.py

Extract binaries (configuration, stage_2 and core) from the fake GZip file. 

### Usage

```text
(venv) $$> python gzip-variant\extract_gzip.py -h
usage: extract_gzip.py [-h] input output     

positional arguments:
  input       Input file
  output      Output directory

options:
  -h, --help  show this help message and exit
```

## gzip-variant/extract_payloads_from_core.py

Extract and decrypt payloads from the core binary, currently only extract the browser hook payloads. VNC server extraction is planned in a futur update.

### Usage

```text
(venv) $$> python gzip-variant\extract_payloads_from_core.py -h
usage: extract_payloads_from_core.py [-h] input output     

positional arguments:
  input       Input file
  output      Output directory

options:
  -h, --help  show this help message and exit
```

## gzip-variant/load_core.py

Load ICEDID's core custom binary into the Python process.  Will wait for user input before calling entrypoint.

You can find an example of context file at `gzip-variant/context.example.json`.

### Usage

```text
(venv) $$> python gzip-variant\load_core.py -h
usage: load_core.py [-h] [-o OFFSET] core_path ctx_path

positional arguments:
  core_path             Core custom PE
  ctx_path              Path to json file defining core's context

options:
  -h, --help            show this help message and exit
  -o OFFSET, --offset OFFSET
                        Offset to real data, skip possible garbage
```

## gzip-variant/read_configuration.py

Parse configuration file and print informations.

### Usage

```text
(venv) $$> python gzip-variant\read_configuration.py -h
usage: read_configuration.py [-h] input      

positional arguments:
  input       Input file

options:
  -h, --help  show this help message and exit
```
