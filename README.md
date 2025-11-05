# PKI 487 (C++)

Generate and verify signed "487" certificates (a simplified X.509 v1 cert with an extra 8-bit Trust Level field), plus a signed CRL. All fields except the signature are human-readable text so you can edit files in a text editor. Any edit breaks the signature and verification will fail, as intended.

Supports integer-only time (no date format). A repository-level `pki_time.txt` stores "PKI system time"; you can change it to simulate not-yet-valid or expired certs.

## Build (Windows, VS Code + CMake + vcpkg)

Prereqs: CMake, a compiler (MSVC), and OpenSSL. The easiest way is vcpkg:

1. Install vcpkg and integrate:
   - https://github.com/microsoft/vcpkg#quick-start-windows
   - `vcpkg integrate install`
2. Install OpenSSL:
   - `vcpkg install openssl:x64-windows`
3. Configure and build (PowerShell):

```powershell
# From the repo root
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release
```

Executable: `build/Release/pki487.exe` (or `build/pki487.exe` for single-config generators).

## Certificate format (CERT487)

```
-----BEGIN CERT487-----
VERSION: 1
SERIAL: <integer>
SIGNATURE-ALGO: SHA256withRSA
ISSUER: <issuer-name>
SUBJECT: <subject-name>
NOT-BEFORE: <int>
NOT-AFTER: <int>
TRUST-LEVEL: <0..7>
SUBJECT-PUBKEY-PEM: BEGIN
<PEM public key>
SUBJECT-PUBKEY-PEM: END
-----END TBS-----
SIGNATURE: <base64 signature over the TBS block above>
-----END CERT487-----
```

## CRL format (CRL487)

```
-----BEGIN CRL487-----
VERSION: 1
SIGNATURE-ALGO: SHA256withRSA
ISSUER: <issuer-name>
THIS-UPDATE: <int>
NEXT-UPDATE: <int>
REVOKED-SERIALS: 1,2,3
-----END TBS-----
SIGNATURE: <base64 signature over the TBS block above>
-----END CRL487-----
```

## Usage (PowerShell)

```powershell
# 0) Initialize PKI time (optional)
./build/Release/pki487.exe pki-time set 0
./build/Release/pki487.exe pki-time show

# 1) Generate keypairs (issuer and subject)
./build/Release/pki487.exe keygen --out keys/ca --bits 2048
./build/Release/pki487.exe keygen --out keys/user --bits 2048

# 2) Issue a certificate (interactive prompts will fill missing fields)
./build/Release/pki487.exe issue-cert --issuer-priv keys/ca_priv.pem --subject-pub keys/user_pub.pem --out certs/user.cert487 --issuer "Demo CA" --subject "Alice" --serial 42 --not-before 0 --not-after 1000 --trust 5

# 3) Verify the certificate
./build/Release/pki487.exe verify-cert --cert certs/user.cert487 --issuer-pub keys/ca_pub.pem --pki-time pki_time.txt --min-tl 3

# 4) Generate a CRL
./build/Release/pki487.exe gen-crl --issuer-priv keys/ca_priv.pem --issuer "Demo CA" --this-update 0 --next-update 1000 --revoked 42 --out crls/ca.crl487

# 5) Verify the CRL
./build/Release/pki487.exe verify-crl --crl crls/ca.crl487 --issuer-pub keys/ca_pub.pem --pki-time pki_time.txt

# 6) Check if a serial is revoked
./build/Release/pki487.exe is-revoked --crl crls/ca.crl487 --serial 42
```

If you edit any field in a CERT487 or CRL487 file, signature verification will fail (expected).

## Notes
- Trust Level is enforced at verification via `--min-tl`. Range is 0..7, with 7 highest.
- Time validity checks use integer times from `pki_time.txt`.
- Canonicalization normalizes newlines and strips trailing whitespace on each line before signing and verifying, so editors that change line endings won't break signatures unintentionally.
- Crypto: RSA (2048+), SHA-256, PKCS#1 v1.5, via OpenSSL.
