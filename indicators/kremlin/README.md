## The extension you never installed: KREMLIN forges Chrome's own integrity checks to steal banking sessions

Elastic Security Labs has tracked REF9334, a Brazilian banking malware operation, since May 2025. Its toolkit is called KREMLIN (as named by the malware author, Kr3mlin4rt1st), though nothing about the operation is Russian. Lures impersonate twelve Brazilian banks; error messages and code comments are written in Portuguese, and the operators' Ethereum transactions cluster during São Paulo working hours. Over 15 months and seven campaigns, they built a malicious browser extension that installs itself in Chrome and Edge, and the browser then loads it as though the user approved it. This post covers the infection chain, the extension internals, all seven campaigns, and the wallet trail connecting them.

Instructions are in the root [indicators](../README.md) directory

Reference: https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware
