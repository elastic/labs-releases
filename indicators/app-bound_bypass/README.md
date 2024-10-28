## Katz and Mouse Game: MaaS Infostealers Adapt to Patched Chrome Defenses

Elastic Security Labs breaks down bypass implementations from the infostealer ecosystem’s reaction to Chrome 127's Application-Bound Encryption scheme.

* Latest versions of infostealers implement bypasses around Google’s recent cookie protection feature using Application-Bound Encryption
* Techniques include integrating offensive security tool ChromeKatz, leveraging COM to interact with Chrome services and decrypt the app-bound encryption key, and using the remote debugging feature within Chrome
* Defenders should actively monitor for different cookie bypass techniques against Chrome on Windows in anticipation of future mitigations and bypasses likely to emerge in the near- to mid-term
* Elastic Security provides mitigations through memory signatures, behavioral rules, and hunting opportunities to enable faster identification and response to infostealer activity


Instructions are in the root [indicators](../README.md) directory

Reference: https://www.elastic.co/security-labs/katz-and-mouse-game
