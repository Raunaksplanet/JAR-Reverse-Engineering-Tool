#!/usr/bin/env python3
"""
JAR Reverse Engineering Tool
Requires: Java installed
pip install requests
"""

import os
import re
import sys
import shutil
import zipfile
import subprocess
from pathlib import Path

import urllib.request
import json


# ─── Config ──────────────────────────────────────────────────────────────────

INTERESTING_PATTERNS = {
    "credentials":  r"(?i)(password|passwd|secret|api[_-]?key|token|bearer|auth)",
    "aws":          r"(?i)(AKIA[0-9A-Z]{16}|aws[_-]?(key|secret|access))",
    "jdbc_url":     r"jdbc:[a-z]+://[^\s\"']+",
    "ip_port":      r"\b\d{1,3}(\.\d{1,3}){3}:\d{2,5}\b",
    "exec":         r"(Runtime\.exec|ProcessBuilder|\.exec\(|cmd\.exe|/bin/sh)",
    "reflection":   r"(Class\.forName|getDeclaredMethod|setAccessible|invoke\()",
    "crypto_weak":  r"(?i)(MD5|SHA1|DES\b|RC4|ECB)",
    "url_hardcode": r"https?://[^\s\"'<>]+",
    "base64_blob":  r"[A-Za-z0-9+/]{40,}={0,2}",
}

DECOMPILERS = {
    "cfr":        ["java", "-jar", "cfr.jar", "{jar}", "--outputdir", "{out}"],
    "fernflower": ["java", "-jar", "fernflower.jar", "{jar}", "{out}"],
    "jadx":       ["jadx", "-d", "{out}", "{jar}"],
}


CFR_JAR = Path(__file__).parent / "cfr.jar"
CFR_RELEASES_API = "https://api.github.com/repos/leibnitz27/cfr/releases/latest"


# ─── CFR Downloader ──────────────────────────────────────────────────────────

def download_cfr(dest: Path = CFR_JAR) -> bool:
    """Auto-download latest cfr.jar from GitHub releases."""
    if dest.exists():
        print(f"[+] cfr.jar already present at {dest}")
        return True

    print("[*] cfr.jar not found — fetching latest release from GitHub...")
    try:
        req = urllib.request.Request(
            CFR_RELEASES_API,
            headers={"User-Agent": "jar-re-tool", "Accept": "application/vnd.github+json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            release = json.loads(resp.read())

        assets = release.get("assets", [])
        jar_asset = next((a for a in assets if a["name"].endswith(".jar")), None)

        if not jar_asset:
            print("[-] No .jar asset found in latest release.")
            return False

        download_url = jar_asset["browser_download_url"]
        name = jar_asset["name"]
        size = jar_asset.get("size", 0)
        print(f"[*] Downloading {name} ({size // 1024} KB) ...")

        def _progress(block_num, block_size, total):
            downloaded = min(block_num * block_size, total)
            pct = int(downloaded / total * 40) if total > 0 else 0
            bar = "█" * pct + "░" * (40 - pct)
            print(f"\r    [{bar}] {downloaded//1024}/{total//1024} KB", end="", flush=True)

        urllib.request.urlretrieve(download_url, dest, reporthook=_progress)
        print(f"\n[+] Saved → {dest}")
        return True

    except Exception as e:
        print(f"[-] Download failed: {e}")
        print(f"    Manual download: https://github.com/leibnitz27/cfr/releases")
        return False


# ─── Core ────────────────────────────────────────────────────────────────────

def extract_jar(jar_path: Path, out_dir: Path):
    """Extract raw JAR contents (classes, resources, manifest)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(jar_path) as zf:
        zf.extractall(out_dir)
    print(f"[+] Extracted {len(list(zf.namelist()))} entries → {out_dir}")


def read_manifest(jar_path: Path) -> dict:
    """Parse META-INF/MANIFEST.MF."""
    with zipfile.ZipFile(jar_path) as zf:
        try:
            raw = zf.read("META-INF/MANIFEST.MF").decode(errors="replace")
            return dict(
                line.split(": ", 1)
                for line in raw.splitlines()
                if ": " in line
            )
        except KeyError:
            return {}


def list_structure(jar_path: Path) -> dict:
    """Summarize JAR structure by file type."""
    counts = {}
    packages = set()
    with zipfile.ZipFile(jar_path) as zf:
        for name in zf.namelist():
            ext = Path(name).suffix or "(no ext)"
            counts[ext] = counts.get(ext, 0) + 1
            if name.endswith(".class"):
                pkg = "/".join(name.split("/")[:-1])
                if pkg:
                    packages.add(pkg)
    return {"file_counts": counts, "packages": sorted(packages)}


def decompile(jar_path: Path, out_dir: Path, tool: str = "cfr") -> bool:
    """Decompile using selected tool. Returns True on success."""
    if tool not in DECOMPILERS:
        print(f"[-] Unknown decompiler: {tool}. Choose from {list(DECOMPILERS)}")
        return False

    # Auto-download cfr.jar if needed
    if tool == "cfr":
        if not download_cfr(CFR_JAR):
            return False
        # Patch cfr command to use resolved path
        DECOMPILERS["cfr"][2] = str(CFR_JAR)

    cmd_template = DECOMPILERS[tool]
    cmd = [c.replace("{jar}", str(jar_path)).replace("{out}", str(out_dir))
           for c in cmd_template]

    # check binary exists for jadx
    if tool == "jadx" and not shutil.which("jadx"):
        print(f"[-] 'jadx' not in PATH. Install: https://github.com/skylot/jadx")
        return False

    if tool == "fernflower":
        jar_file = Path(cmd[2])
        if not jar_file.exists():
            print(f"[-] fernflower.jar not found: {jar_file}")
            return False

    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Decompiling with {tool}...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] Decompiler error:\n{result.stderr[:500]}")
        return False
    print(f"[+] Decompiled → {out_dir}")
    return True


def scan_strings(jar_path: Path) -> dict[str, list[str]]:
    """Extract strings from JAR's constant pool via javap."""
    findings: dict[str, list[str]] = {k: [] for k in INTERESTING_PATTERNS}
    
    with zipfile.ZipFile(jar_path) as zf:
        class_files = [n for n in zf.namelist() if n.endswith(".class")]
    
    # Also scan raw bytes for strings not in class files (resources, configs)
    with zipfile.ZipFile(jar_path) as zf:
        for name in zf.namelist():
            try:
                data = zf.read(name).decode(errors="replace")
            except Exception:
                continue
            for label, pattern in INTERESTING_PATTERNS.items():
                for match in re.finditer(pattern, data):
                    hit = f"[{name}] {match.group()[:120]}"
                    if hit not in findings[label]:
                        findings[label].append(hit)
    return findings


def scan_source(src_dir: Path) -> dict[str, list[str]]:
    """Scan decompiled source for interesting patterns."""
    findings: dict[str, list[str]] = {k: [] for k in INTERESTING_PATTERNS}
    for java_file in src_dir.rglob("*.java"):
        try:
            text = java_file.read_text(errors="replace")
        except Exception:
            continue
        rel = java_file.relative_to(src_dir)
        for label, pattern in INTERESTING_PATTERNS.items():
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pattern, line):
                    hit = f"[{rel}:{i}] {line.strip()[:120]}"
                    if hit not in findings[label]:
                        findings[label].append(hit)
    return findings


def javap_disassemble(class_file: Path) -> str:
    """Run javap on a single .class file."""
    result = subprocess.run(
        ["javap", "-c", "-p", "-verbose", str(class_file)],
        capture_output=True, text=True
    )
    return result.stdout or result.stderr


def print_report(jar_path: Path, manifest: dict, structure: dict,
                 findings: dict, source_findings: dict | None = None):
    sep = "─" * 60

    print(f"\n{'═'*60}")
    print(f"  JAR Analysis: {jar_path.name}")
    print(f"{'═'*60}\n")

    print("[MANIFEST]")
    for k, v in manifest.items():
        print(f"  {k}: {v}")
    print()

    print("[STRUCTURE]")
    for ext, count in sorted(structure["file_counts"].items(), key=lambda x: -x[1]):
        print(f"  {ext:<20} {count}")
    print(f"\n  Top packages ({len(structure['packages'])} total):")
    for pkg in structure["packages"][:20]:
        print(f"    {pkg}")
    print()

    all_findings = findings.copy()
    if source_findings:
        for k in INTERESTING_PATTERNS:
            all_findings[k] = list(set(all_findings.get(k, []) + source_findings.get(k, [])))

    print("[SECURITY FINDINGS]")
    total = 0
    for label, hits in all_findings.items():
        if hits:
            print(f"\n  ▶ {label.upper()} ({len(hits)} hits)")
            for h in hits[:10]:  # cap output
                print(f"    {h}")
            if len(hits) > 10:
                print(f"    ... and {len(hits)-10} more")
            total += len(hits)
    if total == 0:
        print("  No obvious findings (obfuscated or clean).")
    print()


# ─── Main ────────────────────────────────────────────────────────────────────

def analyze(jar_path: str, decompiler: str = "cfr", skip_decompile: bool = False):
    jar = Path(jar_path).resolve()
    if not jar.exists():
        print(f"[-] File not found: {jar}")
        sys.exit(1)

    base = jar.parent / jar.stem
    extract_dir = base / "extracted"
    decompile_dir = base / "src"

    print(f"[*] Target: {jar}")

    manifest = read_manifest(jar)
    structure = list_structure(jar)
    print(f"[*] Main-Class: {manifest.get('Main-Class', 'not set')}")

    extract_jar(jar, extract_dir)
    raw_findings = scan_strings(jar)

    source_findings = None
    if not skip_decompile:
        ok = decompile(jar, decompile_dir, tool=decompiler)
        if ok:
            source_findings = scan_source(decompile_dir)

    print_report(jar, manifest, structure, raw_findings, source_findings)

    # Write findings to file
    report_path = base / "findings.txt"
    with open(report_path, "w") as f:
        for label, hits in raw_findings.items():
            if hits:
                f.write(f"=== {label} ===\n")
                f.write("\n".join(hits) + "\n\n")
    print(f"[+] Findings saved → {report_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="JAR Reverse Engineering Tool")
    parser.add_argument("jar", help="Path to target .jar file")
    parser.add_argument("--decompiler", choices=["jadx", "cfr", "fernflower"],
                        default="jadx", help="Decompiler to use (default: jadx)")
    parser.add_argument("--no-decompile", action="store_true",
                        help="Skip decompilation, only scan raw JAR")
    args = parser.parse_args()

    analyze(args.jar, decompiler=args.decompiler, skip_decompile=args.no_decompile)