import re
import subprocess
import sys
import textwrap
from pathlib import Path

import anthropic

REPO_ROOT = Path(__file__).resolve().parents[2]

COMPONENT_DIRS = {
    "rust": ["core-scanner"],
    "go": ["network-orchestrator"],
    "ebpf": ["ebpf-filter"],
}

BUILD_COMMANDS = {
    "rust": (["cargo", "build", "--release"], REPO_ROOT / "core-scanner"),
    "go": (["go", "build", "-o", "../bin/net-orchestrator", "main.go"], REPO_ROOT / "network-orchestrator"),
    "ebpf": (["make"], REPO_ROOT / "ebpf-filter"),
}

SOURCE_SUFFIXES = {".rs", ".go", ".c", ".h", ".toml", ".mod"}
MAX_ATTEMPTS = 3


def gather_source(dirs):
    files = {}
    for d in dirs:
        base = REPO_ROOT / d
        for path in base.rglob("*"):
            if path.is_file() and (path.suffix in SOURCE_SUFFIXES or path.name == "Makefile"):
                files[str(path.relative_to(REPO_ROOT))] = path.read_text()
    return files


def build_prompt(failure_log, files):
    file_blocks = "\n\n".join(f"--- FILE: {p} ---\n{c}" for p, c in files.items())
    return textwrap.dedent(f"""\
        A CI build failed in the net-suite repository. Failure log:

        {failure_log}

        Current contents of the relevant source files:

        {file_blocks}

        Fix the build failure. Only change what's necessary to make it compile —
        no refactors, renames, or unrelated behavior changes.

        Respond with ONLY the corrected files in exactly this format, nothing else:

        FILE: <relative/path/from/repo/root>
        <complete new file content>
        END_FILE
    """)


def parse_response(text):
    pattern = re.compile(r"FILE: (.+?)\n(.*?)\nEND_FILE", re.DOTALL)
    return {m.group(1).strip(): m.group(2) for m in pattern.finditer(text)}


def run_build(component):
    cmd, cwd = BUILD_COMMANDS[component]
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout + result.stderr


def main():
    component = sys.argv[1]
    failure_log = Path(sys.argv[2]).read_text()[-8000:]

    client = anthropic.Anthropic()
    changed = set()
    verified = False

    for attempt in range(1, MAX_ATTEMPTS + 1):
        files = gather_source(COMPONENT_DIRS[component])
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=8000,
            messages=[{"role": "user", "content": build_prompt(failure_log, files)}],
        )
        text = "".join(b.text for b in response.content if b.type == "text")
        fixes = parse_response(text)

        if not fixes:
            print(f"Attempt {attempt}: no parseable fix returned.")
            break

        for rel_path, content in fixes.items():
            target = REPO_ROOT / rel_path
            if not str(target.resolve()).startswith(str(REPO_ROOT.resolve())):
                continue
            target.write_text(content)
            changed.add(rel_path)

        ok, log = run_build(component)
        if ok:
            verified = True
            break
        print(f"Attempt {attempt} still fails; retrying with new error.")
        failure_log = log[-8000:]

    status = "verified" if verified else "unverified"
    summary = [f"Component: {component}", f"Status: {status}", "", "Files changed:"]
    summary += [f"- {p}" for p in sorted(changed)]

    Path("autofix_summary.txt").write_text("\n".join(summary))
    Path("autofix_status.txt").write_text(status)
    print("\n".join(summary))


if __name__ == "__main__":
    main()
