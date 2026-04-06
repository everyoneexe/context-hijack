"""Assemble bypass results into a runnable project structure."""
from __future__ import annotations

import re
from pathlib import Path

from context_hijack.core.models import AttackResult

# Python stdlib modules (incomplete but covers common ones)
STDLIB_MODULES = {
    "os", "sys", "re", "json", "time", "datetime", "pathlib", "logging",
    "hashlib", "base64", "struct", "socket", "subprocess", "threading",
    "asyncio", "typing", "dataclasses", "collections", "functools",
    "itertools", "abc", "io", "math", "random", "secrets", "shutil",
    "tempfile", "argparse", "configparser", "csv", "xml", "html",
    "http", "urllib", "email", "sqlite3", "contextlib", "copy",
    "enum", "glob", "inspect", "operator", "string", "textwrap",
    "traceback", "unittest", "uuid", "warnings", "weakref", "pickle",
    "platform", "signal", "stat", "ctypes", "multiprocessing",
}

LANG_EXTENSIONS = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "typescript": ".ts",
    "ts": ".ts",
    "bash": ".sh",
    "sh": ".sh",
    "powershell": ".ps1",
    "go": ".go",
    "rust": ".rs",
    "c": ".c",
    "cpp": ".cpp",
    "java": ".java",
    "ruby": ".rb",
    "php": ".php",
}


def extract_code_blocks(text: str) -> list[dict]:
    """Extract code blocks from markdown-formatted AI response.

    Returns list of {lang, code, filename, context} dicts.
    """
    blocks = []
    pattern = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)

    for match in pattern.finditer(text):
        lang = match.group(1).lower() or "python"
        code = match.group(2).strip()

        if len(code) < 20:
            continue

        # Try to find filename from context before the code block
        pre_context = text[max(0, match.start() - 300):match.start()]
        filename = _detect_filename(pre_context, lang, code)

        blocks.append({
            "lang": lang,
            "code": code,
            "filename": filename,
            "context": pre_context[-100:].strip(),
        })

    return blocks


def _detect_filename(context: str, lang: str, code: str) -> str | None:
    """Try to detect filename from surrounding context or code content."""
    # Pattern: `filename.py`, **filename.py**, filename.py:
    patterns = [
        r"`(\w[\w\-/]*\.\w+)`",
        r"\*\*(\w[\w\-/]*\.\w+)\*\*",
        r"(?:file|create|save|called|named)\s+(\w[\w\-/]*\.\w+)",
        r"(\w[\w\-/]*\.(?:py|js|ts|go|rs|c|cpp|java|rb|php|sh))\b",
    ]
    for pat in patterns:
        m = re.search(pat, context, re.IGNORECASE)
        if m:
            return m.group(1)

    # Check first line of code for module docstring or shebang
    first_line = code.split("\n")[0]
    if first_line.startswith("#!"):
        return None
    if '"""' in first_line or "'''" in first_line:
        # Try to extract name from docstring
        m = re.search(r'["\'](\w+)', first_line)
        if m:
            ext = LANG_EXTENSIONS.get(lang, ".py")
            return m.group(1).lower() + ext

    return None


def _extract_requirements(files: list[dict]) -> list[str]:
    """Extract third-party package names from import statements."""
    packages = set()

    for f in files:
        if f["lang"] not in ("python", "py"):
            continue

        for line in f["code"].split("\n"):
            line = line.strip()

            # import X / import X.Y
            m = re.match(r"^import\s+([\w]+)", line)
            if m:
                pkg = m.group(1)
                if pkg not in STDLIB_MODULES and not pkg.startswith("_"):
                    packages.add(pkg)

            # from X import Y
            m = re.match(r"^from\s+([\w]+)", line)
            if m:
                pkg = m.group(1)
                if pkg not in STDLIB_MODULES and not pkg.startswith("_"):
                    packages.add(pkg)

    # Common package name mappings
    name_map = {
        "PIL": "pillow",
        "cv2": "opencv-python",
        "bs4": "beautifulsoup4",
        "yaml": "pyyaml",
        "Crypto": "pycryptodome",
        "sklearn": "scikit-learn",
        "dotenv": "python-dotenv",
    }

    return sorted(name_map.get(p, p) for p in packages if p is not None)


def _slugify(text: str) -> str:
    """Convert text to a safe filename slug."""
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s-]+", "_", text)
    return text[:50].strip("_")


def assemble_project(result: AttackResult, output_dir: str) -> dict:
    """Parse code blocks from attack result and write as project files.

    Returns dict with project stats.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    blocks = extract_code_blocks(result.response)
    if not blocks:
        return {"error": "No code blocks found in response", "files": 0}

    written_files = []
    used_names = set()

    for i, block in enumerate(blocks):
        # Determine filename
        if block["filename"]:
            name = block["filename"]
        else:
            ext = LANG_EXTENSIONS.get(block["lang"], ".py")
            # Try to name from step header
            step_match = re.search(r"Step \d+/\d+: (.+?)(?:\s*──|$)", block["context"])
            if step_match:
                name = f"step_{i+1}_{_slugify(step_match.group(1))}{ext}"
            else:
                name = f"step_{i+1}{ext}"

        # Avoid duplicates
        base_name = name
        counter = 2
        while name in used_names:
            stem, ext_part = name.rsplit(".", 1) if "." in name else (name, "py")
            name = f"{stem}_{counter}.{ext_part}"
            counter += 1
        used_names.add(name)

        # Write file
        filepath = out / name
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(block["code"] + "\n")
        written_files.append({"name": name, "lang": block["lang"], "size": len(block["code"])})

    # Generate requirements.txt
    reqs = _extract_requirements(blocks)
    if reqs:
        (out / "requirements.txt").write_text("\n".join(reqs) + "\n")

    # Generate README
    goal = result.metadata.get("step_goals", [result.metadata.get("category", "unknown")])
    steps_info = ""
    if result.metadata.get("step_goals"):
        for j, g in enumerate(result.metadata["step_goals"]):
            conf = result.metadata.get("step_confidences", [])[j] if j < len(result.metadata.get("step_confidences", [])) else 0
            status = "PASS" if conf >= 0.5 else "FAIL"
            steps_info += f"{j+1}. [{status}] {g}\n"

    readme = f"""# Generated Project

**Goal:** {result.metadata.get('category', 'unknown')} — {', '.join(str(g) for g in goal[:3])}
**Model:** {result.model}
**Confidence:** {result.confidence:.0%}
**Strategy:** {result.strategy}

## Steps
{steps_info}

## Files
{chr(10).join(f'- `{f["name"]}` ({f["lang"]}, {f["size"]} bytes)' for f in written_files)}

## Setup
```bash
pip install -r requirements.txt
```
"""
    (out / "README.md").write_text(readme)

    return {
        "output_dir": str(out),
        "files": len(written_files),
        "file_list": [f["name"] for f in written_files],
        "requirements": reqs,
        "total_code_bytes": sum(f["size"] for f in written_files),
    }
