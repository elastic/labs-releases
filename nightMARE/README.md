<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## Elastic Security Labs - nightMARE

This directory contains the night**MARE** (Malware Analysis & Reverse Engineering) library. nightMARE is a central module that will allow for an efficient and logical approach to automating various reverse engineering functions. 

The nightMARE library is born from the need to refactor our code base into reusable bricks. We want to concentrate logics and dependencies into a single library in order to speed up tool developement for members of the Elastic Security Labs team.

By open sourcing our library to the community we hope that it'll contribute to our battle against threats.

**Please note that this library is still young and under developement. Pull requests are welcome.**  
Example usage: https://www.elastic.co/security-labs/unpacking-icedid

## Malware modules

| Module                             | Description                         |
| ---------------------------------- | ----------------------------------- |
| `nightmare.malware.blister`        | Implement BLISTER algorithms        |
| `nightmare.malware.ghostpulse`     | Implement GHOSTPULSE algorithms     |
| `nightmare.malware.icedid`         | Implement ICEDID algorithms         |
| `nightmare.malware.latrodectus`    | Implement LATRODECTUS algorithms    |
| `nightmare.malware.lobshot`        | Implement LOBSHOT algorithms        |
| `nightmare.malware.nighthawk`      | Implement NIGHTHAWK algorithms      |
| `nightmare.malware.redlinestealer` | Implement REDLINESTEALER algorithms |
| `nightmare.malware.remcos`         | Implement REMCOS algorithms         |
| `nightmare.malware.xorddos`        | Implement XORDDOS algorithms        |
| `nightmare.malware.netwire`        | Implement NetWire algorithms        |
| `nightmare.malware.smokeloader`    | Implement SmokeLoader algorithms    |
| `nightmare.malware.stealc`         | Implement StealC algorithms         |
| `nightmare.malware.strelastealer`  | Implement StrelaStealer algorithms  |



## Install

To install nightMARE, you'll need Python 3.10+. From the `labs-releases/` root directory:

```
# Windows
python -m pip install .\nightMARE

# Linux/macOS
python -m pip install ./nightMARE
```
