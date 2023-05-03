<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## Elastic Security Labs - nightMARE

This directory contains the night**MARE** (Malware Analysis & Reverse Engineering) library. nightMARE will be a central module that will allow for an efficient and logical approach to automating various reverse engineering functions. 

the nightMARE library is born from the need to refactor our code base into reusable bricks. We want to concentrate logics and dependencies into a single library in order to speed up tool developement for members of the Elastic Security Labs team.

By open sourcing our this library to the community we hope that it'll contribute to our battle against threats.

**Please note that this library is still young and under developement. Any contribution is welcomed.**

## Malware Modules

| Module                   | Description                 |
| ------------------------ | --------------------------- |
| nightmare.malware.icedid | Implement ICEDID algorithms |

To install nightMARE, you'll need Python 3.10+:

```
python -m pip install ./nightMARE
```
