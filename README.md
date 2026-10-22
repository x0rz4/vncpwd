# vncpwd 2.0 — VNC Credential & Security Inspector

**English** | [中文](README_zh.md)

Identifies the credentials VNC products store locally, determines which
authentication scheme is actually configured, and rates the exposure.

The tool only reads configuration already present on the local machine. It
does not connect to a network, does not attempt logins, and does not implement
the RA2 or VeNCrypt handshakes.

The original `vncpwd 0.2` was Luigi Auriemma's VNC Password Decoder
(GPL-2.0-or-later) and handled only the classic fixed-key DES format.

---

## Why this is not just "a few more ciphers"

VNC password material falls into three distinct classes. Conflating them leads
to wrong conclusions:

| Class | Location | Recoverable locally |
|---|---|---|
| Server-side password | registry, `ultravnc.ini`, `~/.vnc/passwd` | Yes, for the classic VNC format (fixed-key DES) |
| Viewer-saved connection credential | `*.vnc`, `*.remmina` | Sometimes, depending on the client |
| Remote authentication protocol | RA2, RA2_256, VeNCrypt, MS-Logon, SSO | **No** — no recoverable material exists locally |

So 2.0 aims to recover what can be recovered, explain **why** the rest cannot
be, and point out configuration risks along the way.

## Supported formats and locations

| Product | Location | Format | Auth audit |
|---|---|---|---|
| RealVNC 4–8 | `HKLM\SOFTWARE\RealVNC\vncserver{4,}`, `HKCU\Software\RealVNC` | REG_SZ hex, REG_BINARY | `Authentication`, `Encryption`, `SecurityTypes` |
| TightVNC 2.x | `HKCU`/`HKLM\Software\TightVNC\Server` | `Password`, `PasswordViewOnly` | — |
| TigerVNC (Windows) | `HKCU`/`HKLM\...\TigerVNC\WinVNC4` | REG_SZ hex | `SecurityTypes` (RA2 / RA2_256 / VeNCrypt) |
| TigerVNC (Unix) | `~/.vnc/passwd` | 8 or 16 raw bytes | file permissions |
| UltraVNC | `ultravnc.ini`: `passwd`, `passwd2`, `[admin] passwd` | hex | `MSLogonRequired`, `DSMPlugin`, `AuthRequired`, `UseRegistry` |
| UltraVNC | `HKLM`/`HKCU\SOFTWARE\ORL\WinVNC3` | hex, binary | the `UseRegistry=1` path |
| x11vnc / libvncserver | `~/.vnc/passwd` | 8 or 16 raw bytes | file permissions |
| TurboVNC | `~/.vnc/passwd` | 8 or 16 raw bytes | file permissions |
| Viewer connection files | `*.vnc`, `~/.remmina/*.remmina` | hex, base64(hex) | — |

`--deep` additionally walks each product's registry subtree and resolves any
value whose name contains `pass`, which catches vendor-customised keys.

## Building

Requires CMake ≥ 3.16 and a C17 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

On Windows this produces `build\Release\vncpwd.exe` (MSVC or MinGW).

## Usage

```sh
# scan this machine
vncpwd scan
vncpwd scan --json
vncpwd scan --product tightvnc --show
vncpwd scan --deep

# audit: findings only, suitable for scripting
vncpwd audit
vncpwd audit --json

# check a single ciphertext or file
vncpwd inspect --hex dbd83cfd727a1458
vncpwd inspect --raw '12345678'
vncpwd inspect --file saved.vnc
vncpwd inspect path/to/ultravnc.ini

# list registered product identifiers
vncpwd list
```

| Option | Meaning |
|---|---|
| `--show` | print plaintext; by default secrets are redacted as `p*** (len 8)` |
| `--json`, `--csv` | machine-readable output |
| `--product <id>` | limit to one provider |
| `--deep` | recurse into registry subtrees |
| `-q` | drop the banner (never the result) |

Exit status: `0` no high-risk findings, `1` high or critical findings present,
`2` usage or I/O error. Usable directly in CI or inventory scripts.

## Sample output

```
[TightVNC] Software\TightVNC\Server \ Password
  auth: vnc-password  encoding: binary  cipher: 8 bytes
  password: p******* (len 8)  (confidence 95%)
  note: primary password

Findings
--------
  [high    ] RECOVERABLE-VNC-PASSWORD password stored with the public fixed DES key
             at Software\TightVNC\Server\Password
  [medium  ] WEAK-PASSWORD          password is short or uses a single character class
  [info    ] MAX-LENGTH-PASSWORD    protocol caps the password at 8 characters
```

## Confidence scoring

DES has no MAC and no padding check, so any 8 bytes decrypt to 8 bytes.
A successful decryption therefore says nothing about whether the password was
correct. The tool scores as follows:

- plaintext contains **non-printable bytes** → rejected (`confidence 0.05`);
  this is usually the signature of a wrong guess
- an **all-zero block** → treated as "no password set", not as an empty password
- fully printable ASCII → starts at `0.80`, `+0.10` for exactly 8 bytes,
  `+0.05` for 4 bytes or more
- anything below `0.60` is reported as "not recoverable" rather than guessed at

## Security notes

- Plaintext is **not printed by default**; `--show` is required. Do not put
  `--show` output into shared logs or tickets.
- Access is read-only: no registry key or configuration file is modified.
- The tool contains no remote probing or credential-spraying capability.

**Use only on systems you own or are authorized to assess.**

## Layout

```
include/          public headers
src/core/         DES, encodings, format validation, detection, utilities
src/parsers/      registry, INI, connection-file parsers
src/providers/    per-product location tables and auth audits
src/reports/      text, JSON and CSV output
src/inspector.c   scan / inspect dispatch
tests/            unit tests and CLI end-to-end tests
.github/workflows/build.yml
```

## CI

`.github/workflows/build.yml` runs on GitHub:

- **test** — Ubuntu / macOS / Windows, Debug with `-Werror`
- **sanitizers** — Clang with ASan + UBSan and `-Werror`
- **gcc** — GCC 13 Release with `-Werror`
- **windows** — MSVC x64 and x86, runs the suite, uploads artifacts
- **linux** — statically linked x86_64 and aarch64 binaries
- **release** — on a `v*` tag, collects artifacts and generates checksums

## License

MIT. See [LICENSE](LICENSE).

`src/core/des.c` is derived from Richard Outerbridge's public-domain D3DES,
with the VNC changes copyright AT&T Laboratories Cambridge. Those notices,
and the scope of the MIT grant, are recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

VNC, RealVNC, TightVNC, TigerVNC, UltraVNC and TurboVNC are trademarks of
their respective owners. This project is not affiliated with any of them.
