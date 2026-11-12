# Test Keypairs

> [!WARNING]
> The private and public keys in this directory are dedicated exclusively for local unit tests, CI test runs, and end-to-end integration scenarios (U01–U14).
> 
> **NEVER USE THESE KEYS IN PRODUCTION OR REAL SERVICES.**
> 
> All private keys in this directory are considered publicly compromised and must only be used in ephemeral test fixtures.

## Structure

```
test/keys/
├── rsa-pss-sha256/
│   ├── publisher.key.pem
│   ├── publisher.pub.pem
│   ├── other.key.pem
│   └── other.pub.pem
├── ecdsa-p256-sha256/
│   ├── publisher.key.pem
│   ├── publisher.pub.pem
│   ├── other.key.pem
│   └── other.pub.pem
└── ed25519/
    ├── publisher.key.pem
    ├── publisher.pub.pem
    ├── other.key.pem
    └── other.pub.pem
```

* `publisher.{key,pub}.pem`: Primary keypair authorized in trust store fixtures for package `test-app`.
* `other.{key,pub}.pem`: Secondary/unauthorized keypair used to verify rejection scenarios (`KEY_NOT_TRUSTED`).
