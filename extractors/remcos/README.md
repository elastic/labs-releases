# REMCOS Configuration Extractor by Elastic Security Labs

Elastic Security Labs conducted an in-depth analysis of the REMCOS implant, renowned for its stealthy capabilities, enabling remote access to compromised systems for surveillance and control purposes.

**Supported REMCOS version**: `4.9.3`

**Reference**: [Elastic Security Labs: Dissecting REMCOS RAT - Part One](https://www.elastic.co/security-labs/dissecting-remcos-rat-part-one)

## Install
```bash
$$> virtualenv venv
$$> ./venv/script/activate
(venv) $$> pip install <path-to-esl-repository>/nightMARE
```

## Usage

### Unpack
```bash
(venv) $$> python .\remcos_configuration_extractor.py unpack -h
usage: remcos_configuration_extractor.py unpack [-h] (-f FILE | -d DIRECTORY)

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Input file path
  -d DIRECTORY, --directory DIRECTORY
                        Input directory path
```

### Repack
```bash
(venv) $$> python .\remcos_configuration_extractor.py repack -h
usage: remcos_configuration_extractor.py repack [-h] -i INPUT -o OUTPUT

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file path
  -o OUTPUT, --output OUTPUT
                        Output file path
```

## Examples

### Unpacking file
```bash
(venv) $$> python .\remcos_configuration_extractor.py unpack -f .\corpus\0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5
```

```bash
(venv) $$> ls

    Directory: [redacted]\corpus

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/2/2024  11:40 AM         514048 0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5
-a----          5/2/2024  11:40 AM           3461 0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5.json
```

### Unpacking directory
```bash
python .\remcos_configuration_extractor.py unpack -d .\corpus\
```

### Repacking file
```bash
python .\remcos_configuration_extractor.py repack -i .\corpus\0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5.json -o .\corpus\0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5
```

## Known limitations
- Repacking increases the binary size because the encrypted configuration resource isn't patched; instead, a new one is built by Lief.
- When repacking, modifying a field unpacked using the "int->directory" mapping requires using the exact inverse mapping to restore the proper integer. The current mapping is available [here](https://github.com/elastic/labs-releases/blob/6cd8d281d71d0a74133d2bc41f165523a54f4918/nightMARE/src/nightmare/malware/remcos/configuration.py#L17).