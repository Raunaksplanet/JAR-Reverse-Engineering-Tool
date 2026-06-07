#!/usr/bin/env python3
"""
jar_to_java.py — Decompile a JAR into a proper .java source tree.

- Auto-downloads cfr.jar
- Handles Spring Boot fat JARs (BOOT-INF/classes/)
- Preserves full package directory structure
- Decompiles class-by-class so failures don't abort the whole run
- Prints a summary tree at the end

Usage:
    python3 jar_to_java.py target.jar
    python3 jar_to_java.py target.jar --out ./my_src
    python3 jar_to_java.py target.jar --filter com.silzila   # only decompile matching packages
    python3 jar_to_java.py target.jar --skip-inner           # skip anonymous/inner classes
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

# ── CFR auto-download ────────────────────────────────────────────────────────

CFR_JAR = Path(__file__).parent / "cfr.jar"
CFR_API  = "https://api.github.com/repos/leibnitz27/cfr/releases/latest"


def ensure_cfr() -> Path:
    if CFR_JAR.exists():
        return CFR_JAR
    print("[*] cfr.jar not found — downloading latest from GitHub...")
    try:
        req = urllib.request.Request(
            CFR_API,
            headers={"User-Agent": "jar-to-java", "Accept": "application/vnd.github+json"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            release = json.loads(r.read())
        asset = next(a for a in release["assets"] if a["name"].endswith(".jar"))
        size  = asset.get("size", 0)
        print(f"[*] Downloading {asset['name']} ({size // 1024} KB)...")

        def _progress(n, bs, total):
            done = min(n * bs, total)
            pct  = int(done / total * 40) if total else 0
            print(f"\r    [{'█'*pct}{'░'*(40-pct)}] {done//1024}/{total//1024} KB",
                  end="", flush=True)

        urllib.request.urlretrieve(asset["browser_download_url"], CFR_JAR, _progress)
        print(f"\n[+] Saved → {CFR_JAR}")
        return CFR_JAR
    except Exception as e:
        print(f"[-] Download failed: {e}")
        sys.exit(1)


# ── JAR helpers ──────────────────────────────────────────────────────────────

def extract_classes(jar_path: Path, work_dir: Path) -> Path:
    """
    Extract .class files from a JAR (including Spring Boot fat JARs).
    Spring Boot wraps classes under BOOT-INF/classes/ — we flatten that
    back to a normal package root so cfr sees standard paths.
    Returns the root directory containing .class files.
    """
    classes_dir = work_dir / "classes"
    classes_dir.mkdir(parents=True, exist_ok=True)

    is_spring_boot = False

    with zipfile.ZipFile(jar_path) as zf:
        names = zf.namelist()

        # Detect Spring Boot layout
        boot_prefix = "BOOT-INF/classes/"
        if any(n.startswith(boot_prefix) for n in names):
            is_spring_boot = True
            print("[*] Spring Boot fat JAR detected — extracting BOOT-INF/classes/")

        for name in names:
            if not name.endswith(".class"):
                continue

            if is_spring_boot:
                if not name.startswith(boot_prefix):
                    continue                          # skip embedded lib classes
                rel = name[len(boot_prefix):]        # strip the prefix
            else:
                rel = name

            dest = classes_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(zf.read(name))

    total = sum(1 for _ in classes_dir.rglob("*.class"))
    print(f"[+] Extracted {total} .class files → {classes_dir}")
    return classes_dir


def collect_class_files(classes_dir: Path,
                        pkg_filter: str | None,
                        skip_inner: bool) -> list[Path]:
    """Return sorted list of .class files matching filter options."""
    files = []
    for cf in sorted(classes_dir.rglob("*.class")):
        rel = cf.relative_to(classes_dir).as_posix()

        # Package filter
        if pkg_filter:
            pkg_path = pkg_filter.replace(".", "/")
            if pkg_path not in rel:
                continue

        # Skip inner / anonymous classes (contain $ in filename)
        if skip_inner and "$" in cf.name:
            continue

        files.append(cf)
    return files


# ── Decompiler ───────────────────────────────────────────────────────────────

def decompile_class(cfr: Path, class_file: Path,
                    classes_root: Path, src_out: Path) -> tuple[bool, str]:
    """
    Decompile a single .class file with cfr.
    Writes output to src_out preserving package directory structure.
    Returns (success, error_message).
    """
    rel      = class_file.relative_to(classes_root)          # com/example/Foo.class
    java_rel = rel.with_suffix(".java")                       # com/example/Foo.java
    out_file = src_out / java_rel
    out_file.parent.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["java", "-jar", str(cfr), str(class_file)],
        capture_output=True, text=True
    )

    if result.returncode != 0 or "Decompilation failed" in result.stdout:
        return False, result.stderr.strip() or "cfr returned non-zero"

    source = result.stdout
    if not source.strip():
        return False, "empty output"

    out_file.write_text(source, encoding="utf-8")
    return True, ""


def decompile_all(cfr: Path, class_files: list[Path],
                  classes_root: Path, src_out: Path) -> dict:
    """Decompile all collected class files, return stats."""
    total   = len(class_files)
    ok      = 0
    failed  = []

    print(f"[*] Decompiling {total} classes → {src_out}\n")

    for i, cf in enumerate(class_files, 1):
        rel = cf.relative_to(classes_root)
        bar_pct = int(i / total * 30)
        print(f"\r    [{'█'*bar_pct}{'░'*(30-bar_pct)}] {i}/{total}  {str(rel)[-55:]:<55}",
              end="", flush=True)

        success, err = decompile_class(cfr, cf, classes_root, src_out)
        if success:
            ok += 1
        else:
            failed.append((str(rel), err))

    print(f"\n\n[+] Done — {ok}/{total} succeeded, {len(failed)} failed")
    return {"total": total, "ok": ok, "failed": failed}


# ── Output helpers ────────────────────────────────────────────────────────────

def print_tree(src_out: Path, max_files: int = 60):
    """Print a condensed source tree."""
    print(f"\n{'─'*60}")
    print(f"  Source tree: {src_out}")
    print(f"{'─'*60}")
    java_files = sorted(src_out.rglob("*.java"))
    shown = java_files[:max_files]
    for jf in shown:
        rel = jf.relative_to(src_out)
        depth = len(rel.parts) - 1
        indent = "  " + "│  " * (depth - 1) + "├─ " if depth > 0 else "  "
        print(f"{indent}{rel.parts[-1]}")
    if len(java_files) > max_files:
        print(f"  ... and {len(java_files) - max_files} more files")
    print(f"\n  Total: {len(java_files)} .java files")


def write_failed_log(failed: list, out_dir: Path):
    if not failed:
        return
    log = out_dir / "_decompile_failures.txt"
    with open(log, "w") as f:
        for path, reason in failed:
            f.write(f"{path}\n  → {reason}\n\n")
    print(f"[!] {len(failed)} failures logged → {log}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Decompile JAR → .java source tree with correct package structure"
    )
    parser.add_argument("jar",          help="Target .jar file")
    parser.add_argument("--out",        help="Output directory (default: <jar_name>_src/)")
    parser.add_argument("--filter",     help="Only decompile classes matching this package prefix  e.g. com.silzila")
    parser.add_argument("--skip-inner", action="store_true",
                        help="Skip inner/anonymous classes (those with $ in name)")
    parser.add_argument("--keep-work",  action="store_true",
                        help="Keep temp extracted .class files after decompilation")
    args = parser.parse_args()

    jar = Path(args.jar).resolve()
    if not jar.exists():
        print(f"[-] File not found: {jar}")
        sys.exit(1)

    src_out  = Path(args.out).resolve() if args.out else jar.parent / (jar.stem + "_src")
    work_dir = jar.parent / (jar.stem + "_work")

    print(f"\n[*] Target  : {jar}")
    print(f"[*] Source  : {src_out}")
    if args.filter:
        print(f"[*] Filter  : {args.filter}")
    print()

    # 1. Ensure cfr
    cfr = ensure_cfr()

    # 2. Extract .class files
    classes_root = extract_classes(jar, work_dir)

    # 3. Collect targets
    class_files = collect_class_files(classes_root, args.filter, args.skip_inner)
    if not class_files:
        print("[-] No matching .class files found. Check --filter value.")
        sys.exit(1)
    print(f"[*] Classes to decompile: {len(class_files)}")

    # 4. Decompile
    src_out.mkdir(parents=True, exist_ok=True)
    stats = decompile_all(cfr, class_files, classes_root, src_out)

    # 5. Report
    print_tree(src_out)
    write_failed_log(stats["failed"], src_out)

    # 6. Cleanup
    if not args.keep_work:
        shutil.rmtree(work_dir, ignore_errors=True)

    print(f"\n[+] Java source tree ready → {src_out}\n")


if __name__ == "__main__":
    main()
