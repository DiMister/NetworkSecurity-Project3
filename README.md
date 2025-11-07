# PKI487 Project

Human‑readable “487” certificates (X.509 v1 + 8‑bit trust level) and CRLs. Editing a cert/CRL text invalidates its signature.

## Directory Layout

- include/ : headers
- src/ : implementation
- certs/, crls/, keys/ : generated artifacts
- pki_time.txt : integer “system time” for validity checks

## Build With g++

Prerequisites:
- g++ (C++17 or newer)

### Linux / WSL

```bash
g++ -std=c++17 -O2 -I include \
  src/io.cpp src/util.cpp src/cert487.cpp src/crl487.cpp main.cpp \
  -o pki487
```

Run:
```bash
./pki487
```

### Windows (MinGW-w64)

```powershell
g++ -std=c++17 -O2 -I include src/io.cpp src/util.cpp src/cert487.cpp src/crl487.cpp src/SDESModes.cpp src/SDES.cpp src/MathUtils.cpp src/Rsa.cpp src/encoding.cpp src/CBCHash.cpp main.cpp -o pki487.exe
```

Run:
```powershell
.\pki487.exe
```

### Mac (Clang)



## Usage Examples

Set PKI system time:
```bash
./pki487 pki-time set 0
./pki487 pki-time show
```

Issue cert (auto keygen if not supplied paths):
```bash
./pki487 issue-cert 
```

Verify cert:
```bash
./pki487 verify-cert --cert certs/Alice.cert487 --min-tl 3
```

Generate CRL:
```bash
./pki487 gen-crl
```

Verify CRL:
```bash
./pki487 verify-crl --crl crls/Demo_CA.crl487
```

Check revocation:
```bash
./pki487 is-revoked --crl crls/Demo_CA.crl487 --serial 42
```

## Trust Level

Integer 0–7 stored in TRUST-LEVEL field; `--min-tl` enforces a minimum at verification.

## Expiry

Validity checked against `pki_time.txt` (integer). Adjust with `pki-time set <int>` to force expire/valid states.

-----BEGIN RSA PUBLIC KEY-----
N: 769864357
E: 142112703
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
N: 769864357
D: 409609311
-----END RSA PRIVATE KEY-----
