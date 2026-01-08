# BunnyTunnel
Experimental proxy tunnel software prototype（实验性代理隧道软件原型）

**Warning:**
This project is currently under construction! **Do not use it in any scenario requiring mission-critical security or stealth.**
It should not be considered a mature or reliable solution! Please do not use it in any commercial environments! It is currently imperfect.

**Introduction:**
This is an obfuscated transport layer over TCP. Its goal is to prevent or impede network middleboxes from identifying the underlying traffic based on message content or traffic patterns.
*   **Differences from obfs4:** BunnyTunnel is designed to masquerade as "legitimate communication from an unknown software."
*   **Similarities to obfs4:** Like obfs4, BunnyTunnel aims to provide authentication and data integrity. The connection process occurs in two phases:
    1.  **Phase 1:** A strongly encrypted handshake and key exchange process protected by ML-KEM-1024 (CRYSTALS-Kyber).
    2.  **Phase 2:** Heavily encrypted communication ensues.

**Motivation:**
Development on obfs4 has been slow. Consequently, I interpreted the content of the obfs4 enhancement proposals and instructed an AI to generate an implementation based on my understanding.
The primary goal of BunnyTunnel is to implement an enhanced, obfs4-like protocol. It draws design inspiration from obfs4 and its subsequent enhancement proposals; however, please do not confuse the two projects.

**Threat Model:**
BunnyTunnel's threat model is based on obfs4's, with modified and additional objectives.
*   Building on the passive traffic analysis resistance provided by obfs4, BunnyTunnel offers stronger protection against passive analysis (specifically machine learning-based entropy classification). This is achieved by padding the beginning and end of the data with random-length plaintext ASCII characters.
*   An intermediary (middlebox) should not be able to identify BunnyTunnel traffic without possessing the server's ML-KEM public key.
*   BunnyTunnel is resilient against active attackers. A middlebox should not be able to discover the existence of a BunnyTunnel server through active probing without the server's ML-KEM public key.
*   BunnyTunnel's connection termination behavior remains consistent regardless of the circumstances, standardized as an "immediate connection closure."
*   BunnyTunnel provides protection against specific protocol fingerprinting, particularly through packet size obfuscation and packet inter-arrival timing obfuscation.
*   BunnyTunnel ensures the integrity and confidentiality of the underlying traffic, as well as server authentication.
