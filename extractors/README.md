<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## Elastic Security Labs - Configuration Extractors

This directory contains configuration extractor tools that can be used to collect atomic indicators from malware binaries, organized by family.

In each directory, you'll find all the components needed to run the configuration extractors.

| Component                       | Description                               |
| ------------------------------- | ----------------------------------------- |
| `README.md`                     | Brief description of the extractor family |
| `[malware]_config_extractor.py` | The Python configuration extractor        |

To run the extractors, you'll need Python 3.10+ and the dependent libraries in the `requirements.txt` file in the respective directory:

```
virtualenv venv
./venv/script/activate
pip install <path-to-esl-repository>/nightMARE
```

Once you have the requirements installed, you'll run the extractor against an individual binary or a directory containing multiple samples.

## Example Usage

```
$ python [malware]_config_extractor.py -h

usage: [MALWARE] config file extractor [-h] (-f FILE | -d DIRECTORY)

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  [MALWARE] file path
  -d DIRECTORY, --directory DIRECTORY  [MALWARE] directory
```

## Legacy extractors

If you're looking for our legacy extractors written as Docker containers, you can still find them [here](https://www.elastic.co/security-labs/tools).
