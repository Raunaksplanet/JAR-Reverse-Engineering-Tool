# 🔍 JAR Reverse Engineering Tool

A Python-based static analysis tool for reverse engineering Java `.jar` files. Decompiles bytecode, maps package structure, and scans for hardcoded secrets, weak crypto, dangerous APIs, and more — with zero manual setup for the decompiler.

---

## Features

- **Auto-downloads `cfr.jar`** from GitHub releases — no manual install
- Parses `META-INF/MANIFEST.MF` (Main-Class, classpath, etc.)
- Maps full JAR structure by file type and package tree
- Scans **raw JAR bytes** (classes + resources) for sensitive patterns
- Decompiles to `.java` source and deep-scans for security findings
- Supports `cfr`, `jadx`, and `fernflower` decompilers
- Saves findings report to `findings.txt` alongside the JAR

---

## Requirements

- Python 3.10+
- Java (JDK) installed and in `PATH`
- No pip dependencies — stdlib only (`urllib`, `zipfile`, `subprocess`, `re`)

> For `jadx`: install separately via `brew install jadx` or from [skylot/jadx](https://github.com/skylot/jadx/releases).  
> For `cfr`: **auto-downloaded automatically on first run**.

---

## Installation

```bash
git clone https://github.com/youruser/jar-re-tool.git
cd jar-re-tool
```

No pip install needed.

---

## Usage

```bash
# Full analysis — auto-downloads cfr.jar, decompiles, scans
python jar_reverse.py target.jar

# Use jadx instead
python jar_reverse.py target.jar --decompiler jadx

# Skip decompilation — raw scan only (fast)
python jar_reverse.py target.jar --no-decompile
```

### Arguments

| Argument | Description |
|---|---|
| `jar` | Path to the target `.jar` file |
| `--decompiler` | `cfr` (default), `jadx`, or `fernflower` |
| `--no-decompile` | Skip decompilation; scan raw bytes only |

---

## Output

```
════════════════════════════════════════════════════════════
  JAR Analysis: target.jar
════════════════════════════════════════════════════════════

[MANIFEST]
  Main-Class: com.example.Main
  Class-Path: lib/commons.jar

[STRUCTURE]
  .class               412
  .xml                  18
  .properties            5

  Top packages (34 total):
    com/example/api
    com/example/db
    ...

[SECURITY FINDINGS]

  ▶ CREDENTIALS (3 hits)
    [com/example/db/Config.java:42] private String password = "s3cr3t123";
    ...

  ▶ JDBC_URL (1 hits)
    [application.properties] jdbc:mysql://prod-db.internal:3306/users
    ...
```

Findings are also saved to `<jar_stem>/findings.txt`.

---

## Security Patterns Detected

| Category | What It Catches |
|---|---|
| `credentials` | `password`, `secret`, `api_key`, `token`, `bearer`, `auth` |
| `aws` | `AKIA...` access key IDs, `aws_secret`, `aws_access` |
| `jdbc_url` | Hardcoded database connection strings |
| `ip_port` | Hardcoded internal IPs with ports |
| `exec` | `Runtime.exec`, `ProcessBuilder`, shell invocations |
| `reflection` | `Class.forName`, `getDeclaredMethod`, `setAccessible` |
| `crypto_weak` | `MD5`, `SHA1`, `DES`, `RC4`, `ECB` mode usage |
| `url_hardcode` | Any hardcoded `http://` or `https://` URLs |
| `base64_blob` | Long base64 strings (potential embedded payloads/keys) |

---

## Output Directory Structure

```
target/
├── target.jar
├── extracted/          ← raw JAR contents
│   ├── META-INF/
│   ├── com/example/...
│   └── application.properties
├── src/                ← decompiled Java source
│   └── com/example/...
└── findings.txt        ← all regex hits, grouped by category
```

---

## Decompiler Comparison

| Tool | Auto-download | Obfuscation handling | Modern Java | Notes |
|---|---|---|---|---|
| **cfr** | ✅ Yes | Good | ✅ Excellent | Default; best for lambdas/records |
| **jadx** | ❌ Manual | Good | ✅ Good | Best GUI; also handles APK/AAR |
| **fernflower** | ❌ Manual | Moderate | ✅ Good | IntelliJ's built-in; verbose output |

---

## Handling Obfuscated JARs

If class/method names are `a`, `b`, `aa` (ProGuard/Allatori/Zelix):

1. Check `META-INF/proguard/` — devs sometimes accidentally ship mapping files
2. Use [Recaf](https://github.com/Col-E/Recaf) for interactive remapping
3. Cross-compare multiple decompilers — cfr + jadx often disagree on obfuscated code, revealing more
4. Focus on string constants and method signatures — those survive obfuscation

---

## Legal Disclaimer

This tool is intended for **authorized security research, CTF challenges, and analysis of software you own or have explicit permission to test**. Reverse engineering software without authorization may violate terms of service or applicable law. Use responsibly.

---

## License

MIT
