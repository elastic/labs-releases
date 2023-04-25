<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## Elastic Security Labs - Configuration Extractors

This directory contains configuration extractor tools that can be used to collect atomic indicators from malware binaries, organized by family.

In each directory, you'll find all the components needed to run the configuration extractors.

| Component | Description |
| ------ | ----------- |
| `README.md` | Brief description of the extractor family |
| `requirements.txt` | The Python requirements file for the extractor |
| `[malware]_config_extractor.py` | The Python configuration extractor |

To run the extractors, you'll need Python 3.6+ and the dependent libraries in the `requirements.txt` file in the respective directory:

```
python -m pip install -r requirements.txt
```

Once you have the requirements installed, you'll run the extractor against an individual binary or a directory containing multiple samples.

```
# Single binary
python [malware]_config_extractor.py --file malware.bin

# Directory of samples
python [malware]_config_extractor.py --directory malware-directory
```

## Legacy extractors

If you're looking for our legacy extractors written as Docker containers, you can still find them [here](https://www.elastic.co/security-labs/tools).
