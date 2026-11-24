#!/usr/bin/env python3
"""Add Veracode SAST, SCA and IaC/Secrets jobs to existing GitHub Actions workflows.

Works on a local workflow file or on GitHub targets (org, org/repo, org/pattern*),
where it commits the change to a new branch. Community tool, not an official
Veracode product. See docs/how-it-works.md.
"""
from __future__ import annotations

import argparse
import base64
import csv
import difflib
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install -r requirements.txt")

VERSION = "1.0.0"
TOOL = "veracode-pipeline-inject"

# Pinned actions. --pin-sha resolves the tags to commit SHAs at run time.
ACTIONS = {
    "checkout": "actions/checkout@v6",
    "upload": "actions/upload-artifact@v7",
    "download": "actions/download-artifact@v8",
    "pipeline": "veracode/Veracode-pipeline-scan-action@v1.0.25",
    "policy": "veracode/uploadandscan-action@v0.2.4",
    "sca": "veracode/veracode-sca@v2.1.20",
    "iac": "veracode/container_iac_secrets_scanning@v1.0.9",
}

DOCS = {
    "packaging": "https://docs.veracode.com/r/compilation_packaging",
    "java": "https://docs.veracode.com/r/compilation_java",
    "dotnet": "https://docs.veracode.com/r/compilation_net",
    "js": "https://docs.veracode.com/r/compilation_jscript",
    "creds": "https://docs.veracode.com/r/t_create_api_creds",
    "sca_agent": "https://docs.veracode.com/r/t_sc_cli_agent",
    "tool": "https://github.com/ancient-cthulhu/Veracode-Pipeline-Inject",
}

SECRET_API = ("VERACODE_API_ID", "VERACODE_API_KEY")
SECRET_SCA = "SRCCLR_API_TOKEN"

DEFAULTS = {
    "branch": "veracode/integration",
    "workflow": None,
    "build_job": None,
    "build_step": None,
    "artifact_path": None,       # list of upload-artifact path lines
    "pr_gate_policy": "Veracode Recommended Very High",
    "branch_fail_on_severity": "",
    "runner": "ubuntu-latest",
    "sast": "auto",              # auto | on | off
    "sca": "auto",               # auto | on | off
    "iac": "on",                 # on | artifacts | off
    "windows_runner": "windows-latest",  # SCA runner for Windows-only .NET/C++ repos; "off" disables
    "sca_blocking": False,
    "iac_blocking": False,
    "retention_days": 3,
}
CONFIG_KEYS = set(DEFAULTS)

BEGIN = "# >>> veracode-pipeline-inject >>> managed block: re-run the tool to update it"
END_PREFIX = "# <<< veracode-pipeline-inject <<<"
JOB_IDS = ("veracode-prepare", "veracode-pipeline-scan", "veracode-policy-scan",
           "veracode-sca", "veracode-iac")
UPLOAD_STEP_NAME = "Upload build output for Veracode"
BUILD_ARTIFACT = "veracode-build"
TODO_PATH = "TODO-set-your-build-output-path"


class ToolError(Exception):
    """User, config or detection error (exit 2 in local mode, repo skipped in bulk)."""


class Skip(Exception):
    """Repo cannot be handled safely; reported, not fatal."""


# --------------------------------------------------------------------------- #
# YAML loading
# --------------------------------------------------------------------------- #

class _Loader(yaml.SafeLoader):
    pass


# YAML 1.1 reads `on:` as a bool; keep only true/false as booleans.
_Loader.yaml_implicit_resolvers = {
    k: [r for r in v if r[0] != "tag:yaml.org,2002:bool"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF"))


def load_yaml(text: str):
    return yaml.load(text, Loader=_Loader)


def compose_yaml(text: str):
    return yaml.compose(text, Loader=_Loader)


def node_get(mapping, key):
    if not isinstance(mapping, yaml.MappingNode):
        return None, None
    for k, v in mapping.value:
        if isinstance(k, yaml.ScalarNode) and k.value == key:
            return k, v
    return None, None


def node_end_line(node) -> int:
    """Index of the first line after the node's content."""
    if isinstance(node, yaml.MappingNode) and node.value and not node.flow_style:
        k, v = node.value[-1]
        return max(node_end_line(k), node_end_line(v))
    if isinstance(node, yaml.SequenceNode) and node.value and not node.flow_style:
        return node_end_line(node.value[-1])
    m = node.end_mark
    return m.line if m.column == 0 else m.line + 1


def last_scalar(node):
    while True:
        if isinstance(node, yaml.MappingNode) and node.value and not node.flow_style:
            node = node.value[-1][1]
        elif isinstance(node, yaml.SequenceNode) and node.value and not node.flow_style:
            node = node.value[-1]
        else:
            return node


def insertion_line(node, lines: list[str]) -> int:
    """Line index right after the node's content, before trailing blank lines."""
    end = min(node_end_line(node), len(lines))
    tail = last_scalar(node)
    keep = isinstance(tail, yaml.ScalarNode) and tail.style in ("|", ">") and tail.value.endswith("\n\n")
    if not keep:
        while end > 0 and not lines[end - 1].strip():
            end -= 1
    return end


# --------------------------------------------------------------------------- #
# Managed blocks
# --------------------------------------------------------------------------- #

def block_hash(body: list[str]) -> str:
    joined = "\n".join(line.rstrip() for line in body)
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def strip_managed(text: str) -> tuple[str, int, int]:
    """Remove managed blocks. Returns (text, blocks removed, blocks edited by hand)."""
    lines = text.splitlines(keepends=True)
    out, body, inside, removed, edited = [], [], False, 0, 0
    for line in lines:
        s = line.strip()
        if not inside and s == BEGIN:
            inside, body = True, []
            continue
        if inside:
            if s.startswith(END_PREFIX):
                stored = s[len(END_PREFIX):].strip()
                body_rel = _dedent(body)
                if stored != block_hash(body_rel):
                    edited += 1
                inside = False
                removed += 1
            else:
                body.append(line.rstrip("\r\n"))
            continue
        out.append(line)
    if inside:
        raise ToolError("Unterminated veracode-pipeline-inject block (END marker missing).")
    return "".join(out), removed, edited


def _dedent(body: list[str]) -> list[str]:
    indents = [len(b) - len(b.lstrip(" ")) for b in body if b.strip()]
    cut = min(indents) if indents else 0
    return [b[cut:] if b.strip() else "" for b in body]


def wrap_block(body: list[str], indent: int, eol: str) -> list[str]:
    pad = " " * indent
    lines = [pad + BEGIN + eol]
    lines += [(pad + b if b else "") + eol for b in body]
    lines.append(f"{pad}{END_PREFIX} {block_hash(body)}{eol}")
    return lines


# --------------------------------------------------------------------------- #
# Repository detection: which scans make sense.
# Rules adapted from Workflow-App-per-Lang-Override (standalone copy, keep in sync by hand).
# --------------------------------------------------------------------------- #

MIN_LANGUAGE_BYTES = 200
SAST_LANGUAGES = {
    "C#", "F#", "Visual Basic .NET", "ASP.NET", "Go", "Java", "Groovy", "JavaScript", "TypeScript",
    "Vue", "JSX", "Svelte", "Kotlin", "PHP", "Python", "Ruby", "Scala", "Apex", "ColdFusion", "C", "C++",
}
COMPILED_LANGS = {"Java", "Kotlin", "Scala", "Groovy", "C#", "F#", "Visual Basic .NET", "ASP.NET", "C", "C++"}
SOURCE_LANGS = SAST_LANGUAGES - COMPILED_LANGS
# Languages found but not scanned by this tool, with the reason shown in the plan.
SAST_TIERS = [
    ("needs a macOS/Xcode build", {"Swift", "Objective-C"}),
    ("no build output this tool can package", {"COBOL"}),
    ("no Pipeline Scan support", {"Perl", "PLSQL", "PL/SQL", "TSQL", "Classic ASP", "RPG",
                                  "Visual Basic 6.0", "VBA", "Dart"}),
]
SAST_BUILD_EVIDENCE = {
    lang: ({"makefile", "gnumakefile", "cmakelists.txt", "meson.build", "build.ninja", "configure.ac",
            "configure", "sconstruct"}, (".vcxproj", ".vcproj", ".mk", ".bb"))
    for lang in ("C", "C++")
}
LANGUAGE_ALIASES = {"TSX": "TypeScript", "Objective-C++": "Objective-C",
                    "ColdFusion CFC": "ColdFusion", "Java Server Pages": "Java"}
CODE_EXTENSIONS = {
    ".cs": "C#", ".cshtml": "C#", ".razor": "C#", ".fs": "F#", ".vb": "Visual Basic .NET",
    ".go": "Go", ".java": "Java", ".jsp": "Java", ".groovy": "Groovy",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".vue": "Vue", ".svelte": "Svelte", ".kt": "Kotlin", ".kts": "Kotlin", ".py": "Python",
    ".rb": "Ruby", ".erb": "Ruby", ".scala": "Scala", ".php": "PHP", ".dart": "Dart",
    ".pl": "Perl", ".pm": "Perl", ".cfm": "ColdFusion", ".cfc": "ColdFusion",
    ".cls": "Apex", ".trigger": "Apex", ".c": "C", ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    ".hpp": "C++", ".hh": "C++", ".h": "C", ".swift": "Swift", ".m": "Objective-C",
    ".mm": "Objective-C", ".cbl": "COBOL", ".cob": "COBOL", ".rs": "Rust", ".ex": "Elixir",
    ".exs": "Elixir",
}
SCA_LANGUAGES = {"C#", "F#", "Visual Basic .NET", "ASP.NET", "Go", "Java", "Groovy", "JavaScript",
                 "TypeScript", "Vue", "JSX", "Svelte", "Kotlin", "PHP", "Python", "Scala"}
SCA_MANIFEST_NAMES = {
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "gradle.lockfile", "build.sbt", "ivy.xml", "build.xml", "gradlew", "mvnw", "libs.versions.toml",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bower.json",
    "pnpm-lock.yaml", "pnpm-workspace.yaml", "requirements.txt", "pipfile", "pipfile.lock",
    "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock", "uv.lock", "pdm.lock",
    "go.mod", "go.sum", "go.work", "go.work.sum", "gopkg.toml", "gopkg.lock", "glide.yaml",
    "glide.lock", "trash.lock", "vendor.json", "godeps.json", "godeps.lock",
    "composer.json", "composer.lock", "gemfile", "gemfile.lock", "gems.rb",
    "packages.config", "project.json", "directory.build.props", "directory.packages.props",
    "global.json", "podfile", "podfile.lock", "makefile", "gnumakefile",
    "cargo.toml", "cargo.lock", "package.swift", "package.resolved", "cartfile",
    "cartfile.resolved", "mix.exs", "mix.lock", "pubspec.yaml", "pubspec.lock", "conanfile.txt",
    "conanfile.py", "vcpkg.json", "bun.lockb", "bun.lock",
}
SCA_MANIFEST_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".sln", ".slnx", ".nuspec", ".jar", ".dll", ".sbt")
# Present but never resolvable on their own (the agent fails with "no build system found").
SCA_SUPPORTING_NAMES = {"global.json", "directory.build.props", "directory.packages.props", "gradlew",
                        "mvnw", "libs.versions.toml", "setup.cfg", "pnpm-workspace.yaml", "go.work.sum"}
SCA_SUPPORTING_SUFFIXES = (".sln", ".slnx")
SCA_IGNORED_NAMES = {"gradle-wrapper.jar", "maven-wrapper.jar"}
SCA_ECOSYSTEMS = [
    ("java", {"Java", "Kotlin", "Groovy", "Scala"},
     {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
      "gradle.lockfile", "build.sbt", "ivy.xml", "build.xml", "gradlew", "mvnw", "libs.versions.toml"},
     (".sbt", ".jar")),
    ("javascript", {"JavaScript", "TypeScript", "Vue", "JSX", "Svelte"},
     {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bower.json",
      "pnpm-lock.yaml", "pnpm-workspace.yaml"}, ()),
    ("python", {"Python"},
     {"requirements.txt", "pipfile", "pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg",
      "poetry.lock", "uv.lock", "pdm.lock"}, ()),
    ("go", {"Go"},
     {"go.mod", "go.sum", "go.work", "go.work.sum", "gopkg.toml", "gopkg.lock", "glide.yaml",
      "glide.lock", "trash.lock", "vendor.json", "godeps.json", "godeps.lock"}, ()),
    ("php", {"PHP"}, {"composer.json", "composer.lock"}, ()),
    ("dotnet", {"C#", "F#", "Visual Basic .NET", "ASP.NET"},
     {"packages.config", "project.json", "directory.build.props", "directory.packages.props",
      "global.json"}, (".csproj", ".fsproj", ".vbproj", ".sln", ".slnx", ".nuspec", ".dll")),
]
# Manifests that show a first-party source-language project (not vendored static JS).
SOURCE_PROJECT_NAMES = {"package.json", "requirements.txt", "pyproject.toml", "setup.py", "pipfile",
                        "go.mod", "composer.json", "gemfile"}
IAC_FILE_NAMES = {
    "dockerfile", "containerfile", ".dockerignore", "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml", "chart.yaml", "values.yaml", "kustomization.yaml",
    "kustomization.yml", "skaffold.yaml", "skaffold.yml", "terragrunt.hcl", ".terraform.lock.hcl",
    ".tflint.hcl", "main.bicep", "azuredeploy.json", "serverless.yml", "serverless.yaml",
    "samconfig.toml", "template.yaml", "template.yml", "cdk.json", "pulumi.yaml", "pulumi.yml",
    "ansible.cfg", "vagrantfile", "crossplane.yaml", "chart.lock", "values.yml",
}
IAC_FILE_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".hcl", ".bicep", ".bicepparam", ".dockerfile",
                     ".containerfile", ".cfn.yaml", ".cfn.yml", ".cfn.json")
IAC_NAME_PREFIXES = ("dockerfile", "docker-compose", "containerfile", "pulumi.", "helmfile")
IAC_DIR_HINTS = ("terraform/", "infra/", "infrastructure/", "iac/", "k8s/", "kubernetes/", "kube/",
                 "helm/", "charts/", "manifests/", "deploy/", "deployment/", "deployments/",
                 "cloudformation/", "cfn/", "sam/", "ansible/", "playbooks/", "roles/", "docker/")
IAC_LANGUAGES = {"HCL", "Dockerfile", "Bicep", "Smarty", "Open Policy Agent", "Terraform Template"}
WINDOWS_FILE_NAMES = {"packages.config", "global.asax"}
WINDOWS_FILE_SUFFIXES = (".vcxproj", ".vcproj", ".aspx", ".ascx", ".asax", ".master", ".asmx",
                         ".sqlproj", ".wixproj")
WINDOWS_WEAK_NAMES = {"app.xaml", "web.config", "app.config", "assemblyinfo.cs", "assemblyinfo.vb"}
WINDOWS_WEAK_SUFFIXES = (".xaml", ".vbproj", ".fsproj")
WINDOWS_PROJECT_MARKERS = ("<targetframeworkversion>", "toolsversion=",
                           "schemas.microsoft.com/developer/msbuild/2003", "<usewpf>true",
                           "<usewindowsforms>true")
# net4x and *-windows TFMs inside <TargetFramework(s)>; MAUI IsOSPlatform conditions don't count.
WINDOWS_TFM_RE = re.compile(r"<targetframeworks?(?:\s(?![^>]*isosplatform)[^>]*)?>"
                            r"[^<]*(?:-windows|\bnet(?:11|20|35|4\d{1,2})\b(?!\.))")
WINDOWS_CORROBORATION = {"C#", "F#", "Visual Basic .NET", "ASP.NET", "C", "C++"}
VENDORED = {"node_modules", "bower_components", "jspm_packages", "vendor", "vendors", "third_party",
            "third-party", "dist", "build", "out", "output", "target", "bin", "obj", ".venv", "venv",
            "__pycache__", "site-packages", ".tox", ".eggs", "pods", "carthage", "deriveddata",
            ".terraform", ".gradle", ".mvn", ".idea", ".vscode", "coverage", ".nyc_output", ".git"}
CLASSIFICATION_VENDORED = {"env", "external", "externals"}
GENERATED_SUFFIXES = (".min.js", ".bundle.js", ".chunk.js", ".min.mjs", ".pb.go", "_pb2.py", ".g.cs",
                      ".designer.cs", ".generated.cs", ".d.ts", ".d.mts", ".d.cts", ".pb.cc", ".pb.h",
                      "_pb.js")
_TOOLING_STEMS = ("webpack.config", "babel.config", "jest.config", "rollup.config", "vite.config",
                  "vitest.config", "tailwind.config", "postcss.config", "next.config", "nuxt.config",
                  "metro.config", "svelte.config", "playwright.config", "cypress.config",
                  "prettier.config", "eslint.config", "commitlint.config", "stylelint.config",
                  "tsup.config", "astro.config")
TOOLING_BASENAMES = {
    "webpack.mix.js", "jest.setup.js", "protractor.conf.js", "karma.conf.js", "gulpfile.js",
    "gruntfile.js", ".eslintrc.js", ".eslintrc.cjs", "build.gradle.kts", "settings.gradle.kts",
} | {f"{s}{e}" for s in _TOOLING_STEMS for e in (".js", ".cjs", ".mjs", ".ts", ".mts", ".cts")}
FRAMEWORK_PLATFORM_DIRS = {"pubspec.yaml": ("android", "ios", "linux", "macos", "windows", "web")}
APPLE_CORROBORATION = ({"podfile", "podfile.lock", "info.plist", "cartfile", "package.swift"},
                       (".pbxproj", ".xcworkspacedata", ".xcscheme", ".swift", ".xcconfig"))
SALESFORCE_CORROBORATION = ({"sfdx-project.json"}, {"force-app", "classes", "triggers", "aura", "lwc"})
DEEP_DOTNET_FILES = 5


@dataclass
class Detection:
    languages: set = field(default_factory=set)
    sast_langs: set = field(default_factory=set)
    sast_reason: str = ""
    sca: bool = False
    sca_reason: str = ""
    iac_artifacts: list = field(default_factory=list)
    windows: str | None = None     # evidence for a Windows SCA runner
    runner_reason: str = ""
    source_projects: list = field(default_factory=list)
    truncated: bool = False

    @property
    def sast(self) -> bool:
        return bool(self.sast_langs) or self.truncated

    @property
    def compiled(self) -> set:
        return self.sast_langs & COMPILED_LANGS

    @property
    def source(self) -> set:
        return self.sast_langs & SOURCE_LANGS

    def iac(self, mode: str) -> tuple[bool, str]:
        if mode == "off":
            return False, "off by config (secret scanning is off too)"
        if self.iac_artifacts:
            return True, f"artifacts: {', '.join(self.iac_artifacts[:4])}"
        if mode == "artifacts":
            if self.truncated:
                return True, "tree truncated, cannot prove there is no IaC; kept on"
            return False, "no IaC/container files (iac: artifacts)"
        return True, "no IaC files, kept on for secret scanning"


def _framework_dirs(lower_paths: list[str]) -> tuple[str, ...]:
    out = set()
    for lp in lower_paths:
        parent, _, base = lp.rpartition("/")
        dirs = FRAMEWORK_PLATFORM_DIRS.get(base)
        if dirs and _scannable(lp):
            prefix = parent + "/" if parent else ""
            out.update(prefix + d + "/" for d in dirs)
    return tuple(sorted(out))


def _scannable(lp: str, classification: bool = False, fw: tuple = ()) -> bool:
    if lp.endswith(GENERATED_SUFFIXES) or (fw and lp.startswith(fw)):
        return False
    for seg in lp.split("/")[:-1]:
        if seg in VENDORED or (classification and seg in CLASSIFICATION_VENDORED):
            return False
    return True


def _ext_language(base: str) -> str | None:
    dot = base.rfind(".")
    return CODE_EXTENSIONS.get(base[dot:]) if dot >= 0 else None


def detect(paths: list[str], linguist: dict | None = None, truncated: bool = False,
           sizes: dict | None = None, read_project=None, deep_dotnet: bool = False) -> Detection:
    """Decide which scans apply. sizes: path -> bytes (None = unknown, counts).
    read_project(path) -> text or None, used to confirm Windows-only .NET projects."""
    sizes = sizes or {}
    det = Detection(truncated=truncated)
    items = [(p, p.replace("\\", "/").lower()) for p in paths]
    lower = [lp for _, lp in items]
    fw = _framework_dirs(lower)

    # Languages: Linguist bytes (minus tooling/scaffolding files) + extension scan.
    folded: dict[str, int] = {}
    for lang, b in (linguist or {}).items():
        canon = LANGUAGE_ALIASES.get(lang, lang)
        folded[canon] = folded.get(canon, 0) + int(b or 0)
    excl_bytes, total_files, excl_files = {}, {}, {}
    for p, lp in items:
        if not _scannable(lp):
            continue
        base = lp.rsplit("/", 1)[-1]
        lang = _ext_language(base)
        if not lang:
            continue
        total_files[lang] = total_files.get(lang, 0) + 1
        if base in TOOLING_BASENAMES or (fw and lp.startswith(fw)):
            excl_files[lang] = excl_files.get(lang, 0) + 1
            excl_bytes[lang] = excl_bytes.get(lang, 0) + (sizes.get(p) or 0)
    dropped = set()
    langs = set()
    small: dict[str, int] = {}
    for lang, b in folded.items():
        if not truncated and excl_files.get(lang) and excl_files[lang] == total_files.get(lang):
            dropped.add(lang)
            continue
        if b - excl_bytes.get(lang, 0) >= MIN_LANGUAGE_BYTES:
            langs.add(lang)
        else:
            small[lang] = b - excl_bytes.get(lang, 0)

    entries = [(p, lp, lp.rsplit("/", 1)[-1]) for p, lp in items if _scannable(lp, False, fw)]
    class_entries = [e for e in entries if _scannable(e[1], True, fw)]
    bases = {b for _, _, b in entries}
    apple_ok = any(b in APPLE_CORROBORATION[0] or b.endswith(APPLE_CORROBORATION[1]) for b in bases)
    sf_ok = any(b in SALESFORCE_CORROBORATION[0] for b in bases) or any(
        seg in SALESFORCE_CORROBORATION[1] for _, lp, _ in entries for seg in lp.split("/")[:-1])
    c_ok = any(b.endswith((".c", ".cpp", ".cc", ".cxx")) or b in ("makefile", "gnumakefile", "cmakelists.txt")
               for b in bases)
    ext_bytes: dict[str, int] = {}
    unknown = set()
    for p, lp, base in class_entries:
        if base in TOOLING_BASENAMES:
            continue
        lang = _ext_language(base)
        ext = base[base.rfind("."):] if lang else ""
        if not lang or (ext == ".m" and not apple_ok) or (ext in (".cls", ".trigger") and not sf_ok) \
                or (ext == ".h" and not c_ok):
            continue
        size = sizes.get(p)
        if size is None:
            unknown.add(lang)
        else:
            ext_bytes[lang] = ext_bytes.get(lang, 0) + size
    langs |= unknown | {l for l, b in ext_bytes.items() if b >= MIN_LANGUAGE_BYTES}
    for l, b in ext_bytes.items():
        if b < MIN_LANGUAGE_BYTES:
            small[l] = max(small.get(l, 0), b)
    small = {l: b for l, b in small.items() if l not in langs and l in SAST_LANGUAGES}
    det.languages = langs

    # SAST.
    sast = langs & SAST_LANGUAGES
    evidence = {lp.rsplit("/", 1)[-1] for lp in lower if not (fw and lp.startswith(fw))}
    no_build = set()
    if not truncated:
        for lang, (names, suffixes) in SAST_BUILD_EVIDENCE.items():
            if lang in sast and not any(b in names or b.endswith(suffixes) for b in evidence):
                no_build.add(lang)
    det.sast_langs = sast - no_build
    not_counted = [f"{l} ({why})" for why, members in SAST_TIERS for l in sorted(langs & members)]
    not_counted += [f"{l} (no Makefile/CMake/vcxproj)" for l in sorted(no_build)]
    if det.sast_langs:
        det.sast_reason = f"languages: {', '.join(sorted(det.sast_langs))}"
        if not_counted:
            det.sast_reason += f"; not scanned: {', '.join(not_counted[:6])}"
    elif truncated:
        det.sast_reason = "tree truncated, no supported language proven; kept on"
    elif not_counted:
        det.sast_reason = f"off: {', '.join(not_counted[:6])}"
    else:
        found = sorted(langs)[:8]
        det.sast_reason = "off: no Pipeline Scan language" + (f" (found {', '.join(found)})" if found else "")
    if not det.sast_langs and small:
        det.sast_reason += "; below " + str(MIN_LANGUAGE_BYTES) + " bytes (stub): " + \
            ", ".join(f"{l} {b} B" for l, b in sorted(small.items()))
    if not det.sast_langs and ".gitmodules" in evidence:
        det.sast_reason += "; .gitmodules present, code in submodules is not scanned"
    if dropped:
        det.sast_reason += f"; ignored {', '.join(sorted(dropped))} (tooling/scaffolding files only)"

    # SCA: an enabling manifest from a supported ecosystem.
    enabling, other, ecos = set(), set(), set()
    for p, lp, base in entries:
        name = p.replace("\\", "/").rsplit("/", 1)[-1]
        if base in SCA_IGNORED_NAMES:
            continue
        is_req = "requirements" in base and base.endswith(".txt")
        if not (base in SCA_MANIFEST_NAMES or base.endswith(SCA_MANIFEST_SUFFIXES) or is_req):
            continue
        groups = [g for g, gl, names, sfx in SCA_ECOSYSTEMS
                  if gl & SCA_LANGUAGES and (base in names or (sfx and base.endswith(sfx))
                                             or (is_req and "requirements.txt" in names))]
        supporting = base in SCA_SUPPORTING_NAMES or base.endswith(SCA_SUPPORTING_SUFFIXES)
        if groups and not supporting:
            enabling.add(name)
            ecos.update(groups)
        else:
            other.add(name)
        if base in SOURCE_PROJECT_NAMES or is_req:
            det.source_projects.append(lp)
    det.sca = bool(enabling) or truncated
    if enabling:
        det.sca_reason = f"manifests: {', '.join(sorted(enabling)[:5])} ({', '.join(sorted(ecos))})"
    elif truncated:
        det.sca_reason = "tree truncated, cannot prove there are no manifests; kept on"
    else:
        det.sca_reason = "off: no supported dependency manifest" + (
            f" (only {', '.join(sorted(other)[:5])}, not resolvable on their own)" if other else "")

    # IaC artifacts (IaC/Secrets runs everywhere unless iac: artifacts/off).
    arts = set()
    for p, lp, base in entries:
        if base in IAC_FILE_NAMES or base.endswith(IAC_FILE_SUFFIXES) or base.startswith(IAC_NAME_PREFIXES):
            arts.add(p.replace("\\", "/").rsplit("/", 1)[-1])
        elif lp.endswith((".yml", ".yaml", ".json")) and "/" in lp and any(
                h in "/" + lp.rsplit("/", 1)[0] + "/" for h in IAC_DIR_HINTS):
            arts.add(p.replace("\\", "/"))
    if not arts and langs & IAC_LANGUAGES:
        arts.update(f"{l} (language)" for l in langs & IAC_LANGUAGES)
    det.iac_artifacts = sorted(arts)

    # Windows runner for the SCA job (the agent builds the project).
    strong, weak, projects = set(), set(), []
    for p, lp, base in entries:
        if base in WINDOWS_FILE_NAMES or base.endswith(WINDOWS_FILE_SUFFIXES):
            strong.add(base)
        elif base in WINDOWS_WEAK_NAMES or base.endswith(WINDOWS_WEAK_SUFFIXES):
            weak.add(base)
        if base.endswith((".csproj", ".vbproj", ".fsproj")):
            projects.append(p)
    projects.sort(key=lambda p: (p.count("/"), p.lower()))
    if read_project and projects and not strong and (weak or deep_dotnet):
        for path in projects[:DEEP_DOTNET_FILES]:
            text = (read_project(path) or "").lower()
            if any(m in text for m in WINDOWS_PROJECT_MARKERS) or WINDOWS_TFM_RE.search(text):
                strong.add(f"{path} (Windows-only project)")
                break
    corroborated = bool(langs & WINDOWS_CORROBORATION or projects)
    if strong and corroborated:
        det.windows = ", ".join(sorted(strong)[:4])
        det.runner_reason = f"Windows build signals: {det.windows}"
    elif strong:
        det.runner_reason = "Windows-like files without .NET/C++ code; kept on Linux"
    elif weak:
        det.runner_reason = f"weak Windows signals ({', '.join(sorted(weak)[:3])}) not confirmed; kept on Linux"
    else:
        det.runner_reason = "portable build; Linux"
    return det


def walk_local(root: Path) -> tuple[list[str], dict]:
    paths, sizes = [], {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in VENDORED]
        rel = os.path.relpath(dirpath, root)
        for f in filenames:
            p = f if rel == "." else f"{rel}/{f}".replace("\\", "/")
            paths.append(p)
            try:
                sizes[p] = os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                sizes[p] = None
    return paths, sizes


# --------------------------------------------------------------------------- #
# Workflow analysis
# --------------------------------------------------------------------------- #

BINARY_TOOLS = [
    ("maven", re.compile(r"(?:^|[\s/])mvnw?(?:\.cmd)?\b[^\n]*?\b(?:package|install|verify|deploy)\b")),
    ("gradle", re.compile(r"(?:^|[\s/])gradlew?(?:\.bat)?\b[^\n]*?\b(?:build|assemble\w*|jar|war|bootJar|bootWar|shadowJar)\b")),
    ("sbt", re.compile(r"(?:^\s*|[;&|]\s*)sbt\b[^\n]*?\b(?:package|assembly|universal:packageBin)\b", re.M)),
    ("ant", re.compile(r"(?:^\s*|[;&|]\s*)ant(?:\s|$)", re.M)),
    ("dotnet-publish", re.compile(r"\bdotnet\s+publish\b")),
    ("dotnet", re.compile(r"\bdotnet\s+build\b|\bmsbuild(?:\.exe)?\b")),
    ("native", re.compile(r"(?:^\s*|[;&|]\s*)(?:make|cmake\s+--build|ninja)(?:\s|$)", re.M)),
]
ANCHOR_RE = re.compile(
    r"\b(?:npm|yarn|pnpm|bun)\s+(?:ci|install|test|run\s+\w+|build)\b|\bpip3?\s+install\b|\bpytest\b"
    r"|\bpoetry\s+(?:install|build)\b|\buv\s+(?:sync|build)\b|\btox\b|\bnox\b"
    r"|\bgo\s+(?:build|test|vet)\b|\bcomposer\s+install\b|\bbundle\s+(?:install|exec)\b"
    r"|\bpython3?\s+-m\s+(?:build|pytest|pip)\b|\bmvnw?\b|\bgradlew?\b|\bdotnet\s+\w+|\bmsbuild\b|\bmake\b"
    r"|\bsbt\b|\bant\b")
BINARY_PATHS = {
    "maven": ["**/target/*.jar", "**/target/*.war", "**/target/*.ear",
              "!**/target/*-sources.jar", "!**/target/*-javadoc.jar", "!**/target/*-tests.jar"],
    "gradle": ["**/build/libs/*.jar", "**/build/libs/*.war", "**/build/outputs/apk/**/*.apk",
               "!**/build/libs/*-sources.jar", "!**/build/libs/*-javadoc.jar",
               "!**/build/libs/*-plain.jar"],
    "dotnet": ["**/bin/**/*.dll", "**/bin/**/*.exe", "**/bin/**/*.pdb"],
    "dotnet-publish": ["**/bin/**/publish/**/*.dll", "**/bin/**/publish/**/*.exe",
                       "**/bin/**/publish/**/*.pdb"],
    "sbt": ["**/target/scala-*/*.jar", "!**/target/scala-*/*-sources.jar", "!**/target/scala-*/*-javadoc.jar"],
    "ant": ["**/dist/**/*.jar", "**/dist/**/*.war", "**/dist/**/*.ear"],
    "native": [],
}
TOOL_LABEL = {"maven": "Maven", "gradle": "Gradle", "sbt": "sbt", "ant": "Ant", "dotnet": ".NET build",
              "dotnet-publish": ".NET publish", "native": "native build"}
PREFERRED_JOB_RE = re.compile(r"build|package|compile|^ci$", re.I)
TEST_JOB_RE = re.compile(r"test|check|verify", re.I)
PREFERRED_WF = ("ci", "build", "main", "pipeline", "build-and-test", "maven", "gradle", "dotnet",
                "node", "nodejs", "node.js", "python", "python-app", "go")
DEPRIORITIZED_WF = re.compile(r"codeql|release|deploy|publish|pages|docs|stale|label|dependabot"
                              r"|lint|sonar|scorecard|veracode", re.I)


@dataclass
class BuildMatch:
    job: str
    step: int
    tool: str
    label: str
    paths: list


@dataclass
class Workflow:
    path: str
    text: str
    data: dict
    root: object

    @property
    def jobs(self) -> dict:
        jobs = self.data.get("jobs")
        return jobs if isinstance(jobs, dict) else {}

    def triggers(self) -> set:
        on = self.data.get("on")
        if isinstance(on, str):
            return {on}
        if isinstance(on, list):
            return {str(x) for x in on}
        if isinstance(on, dict):
            return {str(x) for x in on}
        return set()

    def steps(self, job_id: str) -> list:
        steps = self.jobs.get(job_id, {}).get("steps") if isinstance(self.jobs.get(job_id), dict) else None
        return steps if isinstance(steps, list) else []


def parse_workflow(path: str, text: str) -> Workflow:
    try:
        data = load_yaml(text)
        root = compose_yaml(text)
    except yaml.YAMLError as exc:
        raise ToolError(f"{path}: invalid YAML ({str(exc).splitlines()[0]})") from None
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        raise ToolError(f"{path}: no jobs mapping")
    return Workflow(path, text, data, root)


def step_label(step: dict, index: int) -> str:
    if not isinstance(step, dict):
        return f"step {index + 1}"
    return str(step.get("name") or step.get("id") or step.get("uses") or f"step {index + 1}")


def step_text(step: dict) -> str:
    if not isinstance(step, dict):
        return ""
    parts = [str(step.get("run") or "")]
    uses = str(step.get("uses") or "")
    with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
    if "gradle" in uses and with_.get("arguments"):
        parts.append(f"gradle {with_['arguments']}")
    return "\n".join(parts)


def publish_output(cmd: str) -> str | None:
    m = re.search(r"\bdotnet\s+publish\b[^\n]*?(?:-o|--output)[\s=]+(\"?)([^\s\"]+)\1", cmd)
    if m and "${{" not in m.group(2) and "$" not in m.group(2):
        return m.group(2).rstrip("/")
    return None


def find_builds(wf: Workflow) -> list[BuildMatch]:
    found = []
    for job_id, job in wf.jobs.items():
        if not isinstance(job, dict) or "uses" in job:
            continue
        wd = _working_dir(job)
        for i, step in enumerate(wf.steps(job_id)):
            text = step_text(step)
            for tool, rx in BINARY_TOOLS:
                if rx.search(text):
                    paths = list(BINARY_PATHS[tool])
                    if tool == "dotnet-publish":
                        out = publish_output(text)
                        step_wd = step.get("working-directory") if isinstance(step, dict) else None
                        base = step_wd if isinstance(step_wd, str) and "$" not in step_wd else wd
                        if out:
                            root = out if out.startswith("/") or not base else f"{base.rstrip('/')}/{out}"
                            root = root.lstrip("./") if root.startswith("./") else root
                            paths = [f"{root}/**"]
                    found.append(BuildMatch(job_id, i, tool, step_label(step, i), paths))
                    break
    return found


def _working_dir(job: dict) -> str | None:
    d = job.get("defaults")
    wd = d.get("run", {}).get("working-directory") if isinstance(d, dict) and isinstance(d.get("run"), dict) else None
    return wd if isinstance(wd, str) and "$" not in wd else None


def anchor_jobs(wf: Workflow) -> list[str]:
    out = []
    for job_id, job in wf.jobs.items():
        if not isinstance(job, dict) or "uses" in job or job_id in JOB_IDS:
            continue
        if any(ANCHOR_RE.search(step_text(s)) for s in wf.steps(job_id)):
            out.append(job_id)
    return out


def _rank_jobs(wf: Workflow, job_ids: list[str]) -> list[str]:
    def key(j):
        job = wf.jobs.get(j, {})
        name = f"{j} {job.get('name', '')}" if isinstance(job, dict) else j
        pref = 0 if PREFERRED_JOB_RE.search(name) else 1 if TEST_JOB_RE.search(name) else 2
        return (pref, 1 if isinstance(job, dict) and "if" in job else 0)
    ranked = sorted(job_ids, key=key)
    return [j for j in ranked if key(j) == key(ranked[0])] if ranked else []


def choose_build(wf: Workflow, cfg: dict) -> tuple[BuildMatch | None, list[str]]:
    """Return (build, candidate job ids when ambiguous)."""
    matches = [m for m in find_builds(wf) if m.job not in JOB_IDS]
    if cfg.get("build_job"):
        job = cfg["build_job"]
        if job not in wf.jobs:
            raise ToolError(f"build_job '{job}' not found in {wf.path} (jobs: {', '.join(wf.jobs)})")
        if "uses" in wf.jobs[job]:
            raise ToolError(f"build_job '{job}' calls a reusable workflow; steps cannot be added to it")
        matches = [m for m in matches if m.job == job]
        steps = wf.steps(job)
        if cfg.get("build_step"):
            idx = next((i for i, s in enumerate(steps) if isinstance(s, dict)
                        and cfg["build_step"] in (s.get("name"), s.get("id"))), None)
            if idx is None:
                raise ToolError(f"build_step '{cfg['build_step']}' not found in job '{job}'")
            tool = next((m.tool for m in matches if m.step == idx), "custom")
            return BuildMatch(job, idx, tool, step_label(steps[idx], idx),
                              list(BINARY_PATHS.get(tool, []))), []
        if matches:
            return matches[-1], []
        if cfg.get("artifact_path") and steps:
            return BuildMatch(job, len(steps) - 1, "custom", step_label(steps[-1], len(steps) - 1), []), []
        raise ToolError(f"No build step found in job '{job}'; set build_step or artifact_path")
    if not matches:
        return None, []
    jobs = list(dict.fromkeys(m.job for m in matches))
    best = _rank_jobs(wf, jobs)
    if len(best) > 1:
        return None, best
    job_matches = [m for m in matches if m.job == best[0]]
    return job_matches[-1], []


def existing_upload(wf: Workflow, build: BuildMatch) -> tuple[str, bool] | None:
    """Reuse an upload-artifact step that follows the build step: (name or pattern, is_pattern)."""
    for step in wf.steps(build.job)[build.step + 1:]:
        if not isinstance(step, dict) or "if" in step:
            continue
        uses = str(step.get("uses") or "")
        if not uses.startswith("actions/upload-artifact@"):
            continue
        w = step.get("with") if isinstance(step.get("with"), dict) else {}
        name, path = str(w.get("name") or "artifact"), str(w.get("path") or "")
        if re.search(r"report|coverage|test-results|logs?\b|junit|surefire", f"{name} {path}", re.I):
            continue
        if "${{" in name:
            return re.sub(r"\$\{\{.*?\}\}", "*", name), True
        return name, False
    return None


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #

@dataclass
class Plan:
    workflow: str
    sast_mode: str = "off"          # off | binary | source | binary+source
    build: BuildMatch | None = None
    needs: str | None = None
    upload_paths: list = field(default_factory=list)
    reuse: tuple | None = None
    sca: bool = False
    iac: bool = False
    sca_runner: str | None = None   # set when the SCA job needs another runner (Windows)
    reasons: dict = field(default_factory=dict)
    todos: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def summary(self) -> dict:
        sast = self.sast_mode
        if self.build and self.sast_mode.startswith("binary"):
            sast = f"{self.sast_mode} ({self.build.job}: {TOOL_LABEL.get(self.build.tool, self.build.tool)})"
        elif self.sast_mode == "source" and self.needs:
            sast = f"source (after {self.needs})"
        sca = ("on" + (f" ({self.sca_runner})" if self.sca_runner else "")) if self.sca else "off"
        return {"sast": sast, "sca": sca, "iac": "on" if self.iac else "off"}


def _gh_glob(name: str, pattern: str) -> bool:
    rx = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", ".")
    return re.fullmatch(rx, name) is not None


def push_runs_on(wf: Workflow, branch: str) -> bool:
    """True when a push to `branch` triggers the workflow."""
    on = wf.data.get("on")
    if isinstance(on, str):
        return on == "push"
    if isinstance(on, list):
        return "push" in on
    if not isinstance(on, dict) or "push" not in on:
        return False
    push = on.get("push")
    if not isinstance(push, dict):
        return True
    if "branches" in push:
        hit = False
        for p in push.get("branches") or []:
            p = str(p)
            if p.startswith("!"):
                hit = hit and not _gh_glob(branch, p[1:])
            elif _gh_glob(branch, p):
                hit = True
        return hit
    if "branches-ignore" in push:
        return not any(_gh_glob(branch, str(p)) for p in push.get("branches-ignore") or [])
    return "tags" not in push and "tags-ignore" not in push


def scan_decisions(det: Detection, cfg: dict) -> dict:
    """Per-scan on/off with the reason, before looking at any workflow."""
    out = {}
    if cfg["sast"] == "off":
        out["sast"] = (False, "off by config")
    elif cfg["sast"] == "on" and not det.sast:
        out["sast"] = (True, f"forced on by config ({det.sast_reason})")
    else:
        out["sast"] = (det.sast, det.sast_reason)
    if cfg["sca"] == "off":
        out["sca"] = (False, "off by config")
    elif cfg["sca"] == "on" and not det.sca:
        out["sca"] = (True, f"forced on by config ({det.sca_reason})")
    else:
        out["sca"] = (det.sca, det.sca_reason)
    out["iac"] = det.iac(cfg["iac"])
    win = cfg.get("windows_runner") or "off"
    if out["sca"][0] and det.windows and win != "off":
        out["runner"] = (win, det.runner_reason)
    else:
        out["runner"] = (None, det.runner_reason)
    return out


def make_plan(wf: Workflow, det: Detection, cfg: dict) -> Plan:
    wf = parse_workflow(wf.path, strip_managed(wf.text)[0])
    plan = Plan(wf.path)
    dec = scan_decisions(det, cfg)
    plan.reasons = {k: v[1] for k, v in dec.items()}
    plan.iac = dec["iac"][0]
    plan.sca = dec["sca"][0]
    plan.sca_runner = dec["runner"][0]

    trig = wf.triggers()
    if not trig & {"push", "pull_request"}:
        plan.todos.append("The workflow has no push or pull_request trigger, so the scans only "
                          "run on its other events and SAST never runs. Add push/pull_request to `on:`.")
    else:
        if "pull_request" not in trig:
            plan.notes.append("No pull_request trigger: PR gate scans will not run")
        if "push" not in trig:
            plan.notes.append("No push trigger: the policy scan on the default branch will not run")
        if "pull_request" in trig and not push_runs_on(wf, cfg["branch"]):
            plan.notes.append(f"Pushes to `{cfg['branch']}` don't trigger this workflow; open a PR from it to test")
    conc = wf.data.get("concurrency")
    if isinstance(conc, dict) and conc.get("cancel-in-progress") is True:
        plan.todos.append("Workflow-level `concurrency` cancels in-progress runs, which can cancel a "
                          "policy scan upload on the default branch. Consider "
                          "`cancel-in-progress: ${{ github.ref_name != github.event.repository.default_branch }}`.")

    if not dec["sast"][0]:
        return plan
    want_compiled = bool(det.compiled) or cfg["sast"] == "on" or (det.truncated and not det.sast_langs)
    want_source = bool(det.source)

    build, ambiguous = choose_build(wf, cfg)
    if ambiguous:
        raise Skip(f"several jobs build the code ({', '.join(ambiguous)}); "
                   "set build_job in the config or --build-job")
    if build and (want_compiled or cfg.get("build_job")):
        plan.build = build
        plan.needs = build.job
        # Binaries cover the compiled code; add source only for a real JS/Python/... project.
        plan.sast_mode = "binary+source" if want_source and det.source_projects else "binary"
        reuse = None if cfg.get("artifact_path") else existing_upload(wf, build)
        if reuse:
            plan.reuse = reuse
            plan.notes.append(f"Reusing the build job's artifact '{reuse[0]}'")
        else:
            plan.upload_paths = list(cfg.get("artifact_path") or build.paths) or [TODO_PATH]
            job_label = f"job `{build.job}`"
            if plan.upload_paths == [TODO_PATH]:
                plan.todos.append(f"Set the build output path in step \"{UPLOAD_STEP_NAME}\" ({job_label}); "
                                  f"the tool could not infer it for a {TOOL_LABEL.get(build.tool, build.tool)}. "
                                  f"Packaging guide: {DOCS['packaging']}")
            elif not cfg.get("artifact_path"):
                plan.todos.append(f"Check the build output path in step \"{UPLOAD_STEP_NAME}\" ({job_label}): "
                                  f"it uses the {TOOL_LABEL.get(build.tool, build.tool)} defaults. "
                                  f"Packaging guide: {DOCS['packaging']}")
        if build.tool == "dotnet":
            plan.notes.append(".NET: scan a `dotnet publish` output with .pdb files for best results")
    elif det.compiled:
        if want_source:
            plan.sast_mode = "source"
        plan.todos.append(f"SAST for {', '.join(sorted(det.compiled))} needs a build step "
                          "(Maven, Gradle, dotnet, msbuild or make) in this workflow. Re-run with "
                          f"--build-job/--artifact-path. Packaging guide: {DOCS['packaging']}")
    elif want_source:
        plan.sast_mode = "source"

    if plan.sast_mode == "source":
        anchors = anchor_jobs(wf)
        if anchors:
            plan.needs = _rank_jobs(wf, anchors)[0]
    if plan.build and plan.sast_mode.startswith("binary") and wf.jobs.get(plan.build.job, {}).get("strategy"):
        plan.notes.append(f"Build job `{plan.build.job}` uses a matrix; matching output file names are scanned once")
    return plan


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

PREPARE_SCRIPT = r'''import json, os, pathlib, shutil, subprocess, zipfile
DOCS = "https://docs.veracode.com/r/"
build, out = pathlib.Path("veracode-build"), pathlib.Path("veracode-units")
out.mkdir(exist_ok=True)
def warn(msg, page="compilation_packaging"):
    print(f"::warning title=Veracode packaging::{msg} See {DOCS}{page}")
files = sorted(p for p in build.rglob("*") if p.is_file()) if build.is_dir() else []
JAVA = (".jar", ".war", ".ear", ".apk", ".aab")
NATIVE = (".dll", ".exe", ".pdb", ".so", ".dylib")
SKIP = ("-sources.jar", "-javadoc.jar", "-tests.jar", "-plain.jar")
units = []
def add(src):
    dest, n = out / src.name, 1
    while dest.exists():
        dest, n = out / f"{src.stem}-{n}{src.suffix}", n + 1
    shutil.copyfile(src, dest)
    units.append(dest.name)
for p in files:
    if p.name.lower().endswith(JAVA) and not p.name.lower().endswith(SKIP):
        add(p)
native = [p for p in files if p.suffix.lower() in NATIVE]
if native:
    with zipfile.ZipFile(out / "veracode-binaries.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            if not p.name.lower().endswith(JAVA):
                z.write(p, p.relative_to(build))
    units.append("veracode-binaries.zip")
    bins = [p for p in native if p.suffix.lower() in (".dll", ".exe")]
    if bins and not any(p.suffix.lower() == ".pdb" for p in native):
        warn("No .pdb files next to the .dll/.exe files. Build with debug symbols (portable PDBs) so findings show file and line.", "compilation_net")
    tests = sorted({p.name for p in bins if "test" in p.name.lower()})
    if tests:
        warn(f"Test assemblies in the build output ({', '.join(tests[:5])}). Exclude test projects from the upload path.", "compilation_net")
if os.environ.get("SOURCE_ZIP") == "true":
    subprocess.run(["git", "archive", "--format=zip", "-o", str(out / "veracode-source.zip"), "HEAD"], check=True)
    units.append("veracode-source.zip")
    with zipfile.ZipFile(out / "veracode-source.zip") as z:
        names = z.namelist()
    if any("node_modules/" in n for n in names):
        warn("node_modules is committed to the repository. Remove it from the scanned source.", "compilation_jscript")
    js = [n for n in names if n.endswith(".js")]
    if js and all(n.endswith(".min.js") for n in js):
        warn("Only minified JavaScript found. Scan the unminified source.", "compilation_jscript")
for name in units:
    path = out / name
    if path.suffix.lower() in (".jar", ".war", ".ear"):
        try:
            with zipfile.ZipFile(path) as z:
                cls = [n for n in z.namelist() if n.endswith(".class")][:25]
                if cls and not any(b"LineNumberTable" in z.read(n) for n in cls):
                    warn(f"{name}: classes compiled without debug info. Compile with -g so findings show line numbers.", "compilation_java")
                if any(n.endswith("Test.class") or "/test/" in n for n in z.namelist()):
                    warn(f"{name}: contains test classes. Package the application without tests.", "compilation_java")
        except zipfile.BadZipFile:
            warn(f"{name} is not a valid archive.")
    if path.stat().st_size > 2 * 1024 ** 3:
        warn(f"{name} is larger than 2 GB, the per-file upload limit.", "c_static_overview")
if not units:
    warn("No scannable build output found. Check the build output path uploaded for Veracode.")
print("Scan units:", units)
with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
    fh.write(f"units={json.dumps(units)}\n")'''

FORK_GUARD = "github.event_name != 'pull_request' || github.event.pull_request.head.repo.fork == false"


def _q(value: str) -> str:
    """Single-quoted string for a GitHub expression."""
    return "'" + value.replace("'", "''") + "'"


def _yq(value: str) -> str:
    """YAML scalar, quoted when needed."""
    if re.fullmatch(r"[A-Za-z0-9_./@*!-]+", value) and not value.startswith(("*", "!", "-", "@")):
        return value
    return "'" + value.replace("'", "''") + "'"


def render_upload_step(plan: Plan, cfg: dict, actions: dict) -> list[str]:
    lines = [
        f"- name: {UPLOAD_STEP_NAME}",
        f"  uses: {actions['upload']}",
        "  with:",
        f"    name: {BUILD_ARTIFACT}-${{{{ strategy.job-index }}}}",
        "    path: |",
    ]
    lines += [f"      {p}" for p in plan.upload_paths]
    lines += ["    if-no-files-found: warn", f"    retention-days: {int(cfg['retention_days'])}"]
    return lines


def render_jobs(plan: Plan, cfg: dict, actions: dict) -> list[str]:
    runner = _yq(str(cfg["runner"]))
    out: list[str] = []
    perms = ["  permissions:", "    contents: read"]
    if plan.sast_mode != "off":
        out += ["veracode-prepare:", "  name: Veracode SAST prepare"]
        if plan.needs:
            out.append(f"  needs: {plan.needs}")
        out += [f"  if: {FORK_GUARD}", f"  runs-on: {runner}", *perms,
                "  outputs:", "    units: ${{ steps.units.outputs.units }}", "  steps:"]
        source = "source" in plan.sast_mode
        if source:
            out += ["    - name: Checkout", f"      uses: {actions['checkout']}"]
        if plan.sast_mode.startswith("binary"):
            out += ["    - name: Download build output", f"      uses: {actions['download']}", "      with:"]
            if plan.reuse and not plan.reuse[1]:
                out.append(f"        name: {_yq(plan.reuse[0])}")
            else:
                pattern = plan.reuse[0] if plan.reuse else f"{BUILD_ARTIFACT}-*"
                out += [f"        pattern: {_yq(pattern)}", "        merge-multiple: true"]
            out.append(f"        path: {BUILD_ARTIFACT}")
        out += ["    - name: Package and check for Veracode", "      id: units", "      shell: bash",
                "      env:", f"        SOURCE_ZIP: '{'true' if source else 'false'}'",
                "      run: |", "        python3 - <<'PY'"]
        out += [f"        {line}" if line else "" for line in PREPARE_SCRIPT.splitlines()]
        out += ["        PY",
                "    - name: Upload scan units", "      if: steps.units.outputs.units != '[]'",
                f"      uses: {actions['upload']}", "      with:", "        name: veracode-scan-units",
                "        path: veracode-units/", f"        retention-days: {int(cfg['retention_days'])}"]

        policy = cfg["pr_gate_policy"] or ""
        sev = cfg["branch_fail_on_severity"] or ""
        out += [
            "veracode-pipeline-scan:",
            "  name: Veracode Pipeline Scan (${{ matrix.unit }})",
            "  needs: veracode-prepare",
            "  if: >-",
            "    needs.veracode-prepare.outputs.units != '[]' &&",
            "    (github.event_name == 'pull_request' ||",
            "    (github.event_name == 'push' && github.ref_name != github.event.repository.default_branch))",
            f"  runs-on: {runner}", *perms,
            "  strategy:", "    fail-fast: false", "    matrix:",
            "      unit: ${{ fromJSON(needs.veracode-prepare.outputs.units) }}",
            "  steps:",
            "    - name: Download scan units", f"      uses: {actions['download']}", "      with:",
            "        name: veracode-scan-units", "        path: veracode-units",
            "    - name: Veracode Pipeline Scan", f"      uses: {actions['pipeline']}", "      with:",
            "        vid: ${{ secrets.VERACODE_API_ID }}", "        vkey: ${{ secrets.VERACODE_API_KEY }}",
            "        file: veracode-units/${{ matrix.unit }}",
        ]
        if policy:
            out += ["        # PR: gate on the policy. Branch push: any flaw fails.",
                    f"        veracode_policy_name: ${{{{ github.event_name == 'pull_request' && {_q(policy)} || '' }}}}"]
        if sev:
            out.append(f"        fail_on_severity: ${{{{ github.event_name != 'pull_request' && {_q(sev)} || '' }}}}")
        out += ["        fail_build: true", "        issue_details: true",
                "        artifact_name: ${{ matrix.unit }}"]
        out += [
            "veracode-policy-scan:",
            "  name: Veracode Policy Scan",
            "  needs: veracode-prepare",
            "  if: >-",
            "    needs.veracode-prepare.outputs.units != '[]' &&",
            "    github.event_name == 'push' && github.ref_name == github.event.repository.default_branch",
            f"  runs-on: {runner}", *perms,
            "  # Never cancel an in-flight policy upload.",
            "  concurrency:", "    group: veracode-policy-${{ github.repository }}",
            "    cancel-in-progress: false",
            "  steps:",
            "    - name: Download scan units", f"      uses: {actions['download']}", "      with:",
            "        name: veracode-scan-units", "        path: veracode-units",
            "    - name: Veracode Upload and Scan", f"      uses: {actions['policy']}", "      with:",
            "        vid: ${{ secrets.VERACODE_API_ID }}", "        vkey: ${{ secrets.VERACODE_API_KEY }}",
            "        appname: ${{ secrets.VERACODE_APP_NAME || github.repository }}",
            "        createprofile: true",
            "        filepath: veracode-units",
            "        version: ${{ github.ref_name }}-${{ github.run_number }}-${{ github.run_attempt }}",
        ]
    if plan.sca:
        sca_runner = _yq(plan.sca_runner) if plan.sca_runner else runner
        out += ["veracode-sca:", "  name: Veracode SCA", f"  if: {FORK_GUARD}", f"  runs-on: {sca_runner}",
                *perms, "  steps:", "    - name: Checkout", f"      uses: {actions['checkout']}",
                "    - name: Veracode agent-based SCA"]
        if not cfg["sca_blocking"]:
            out.append("      continue-on-error: true")
        out += [f"      uses: {actions['sca']}", "      env:",
                f"        {SECRET_SCA}: ${{{{ secrets.{SECRET_SCA} }}}}", "      with:",
                "        create-issues: false", "        recursive: true", "        update_advisor: true",
                "        allow-dirty: true"]
        if cfg["sca_blocking"]:
            out.append("        breakBuildOnPolicyFindings: true")
    if plan.iac:
        out += ["veracode-iac:", "  name: Veracode IaC and Secrets", f"  if: {FORK_GUARD}",
                f"  runs-on: {runner}", *perms, "  steps:", "    - name: Checkout",
                f"      uses: {actions['checkout']}", "    - name: Veracode IaC and Secrets scan"]
        if not cfg["iac_blocking"]:
            out.append("      continue-on-error: true")
        out += [f"      uses: {actions['iac']}", "      with:",
                "        vid: ${{ secrets.VERACODE_API_ID }}", "        vkey: ${{ secrets.VERACODE_API_KEY }}",
                "        command: scan", "        type: directory", "        source: ./",
                "        format: table", f"        fail_build: {'true' if cfg['iac_blocking'] else 'false'}"]
    return out


# --------------------------------------------------------------------------- #
# Injection
# --------------------------------------------------------------------------- #

def _eol(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def inject(text: str, plan: Plan, cfg: dict, actions: dict, force: bool = False) -> str:
    base, _, edited = strip_managed(text)
    if edited and not force:
        raise Skip("a managed block was edited by hand; keep the edit or re-run with --force")
    wf = parse_workflow(plan.workflow, base)
    clash = [j for j in JOB_IDS if j in wf.jobs]
    if clash:
        raise Skip(f"job ids already used: {', '.join(clash)}")
    eol = _eol(base)
    lines = base.splitlines(keepends=True)
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += eol

    _, jobs_node = node_get(wf.root, "jobs")
    if not isinstance(jobs_node, yaml.MappingNode) or jobs_node.flow_style or not jobs_node.value:
        raise Skip("`jobs:` must be a non-empty block mapping")
    job_indent = jobs_node.value[0][0].start_mark.column
    inserts: list[tuple[int, int, list[str]]] = []
    body = render_jobs(plan, cfg, actions)
    if body:
        # Same line as the upload step: jobs go after it (applied first, bottom-up).
        inserts.append((insertion_line(jobs_node, lines), 1, wrap_block(body, job_indent, eol)))

    if plan.build and plan.upload_paths and plan.sast_mode.startswith("binary"):
        _, job_node = node_get(jobs_node, plan.build.job)
        _, steps_node = node_get(job_node, "steps")
        if not isinstance(steps_node, yaml.SequenceNode) or steps_node.flow_style:
            raise Skip(f"job `{plan.build.job}` steps must be a block list")
        step_node = steps_node.value[plan.build.step]
        line = lines[step_node.start_mark.line]
        key_col = step_node.start_mark.column
        dash_col = line.rfind("-", 0, key_col)
        if dash_col < 0:
            raise Skip(f"cannot locate the build step list item in job `{plan.build.job}`")
        rel = render_upload_step(plan, cfg, actions)
        gap = key_col - dash_col
        step_lines = [rel[0].replace("- ", "-" + " " * (gap - 1), 1)] + \
                     [(" " * (gap - 2)) + r for r in rel[1:]]
        inserts.append((insertion_line(step_node, lines), 0, wrap_block(step_lines, dash_col, eol)))

    for at, _, block in sorted(inserts, key=lambda x: (x[0], x[1]), reverse=True):
        lines[at:at] = block
    new = "".join(lines)
    verify_additions(base, new, plan)
    return new


def verify_additions(base: str, new: str, plan: Plan) -> None:
    """The client's jobs must be unchanged except for the one added upload step."""
    try:
        before, after = load_yaml(base), load_yaml(new)
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        raise ToolError(f"generated YAML does not parse: {exc}") from None
    after_jobs = dict(after["jobs"])
    for j in JOB_IDS:
        after_jobs.pop(j, None)
    if plan.build and plan.upload_paths and plan.sast_mode.startswith("binary"):
        steps = after_jobs[plan.build.job]["steps"]
        added = steps.pop(plan.build.step + 1)
        if added.get("name") != UPLOAD_STEP_NAME:
            raise ToolError("internal error: upload step landed in the wrong place")
    if after_jobs != before["jobs"] or {k: v for k, v in after.items() if k != "jobs"} != \
            {k: v for k, v in before.items() if k != "jobs"}:
        raise ToolError("internal error: injection changed the client's workflow")


def remove(text: str, force: bool = False) -> str:
    new, removed, edited = strip_managed(text)
    if edited and not force:
        raise Skip("a managed block was edited by hand; re-run with --force to remove it anyway")
    return new


def unified_diff(old: str, new: str, path: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        f"a/{path}", f"b/{path}"))


def has_other_veracode(wf: Workflow) -> bool:
    base, _, _ = strip_managed(wf.text)
    return bool(re.search(r"uses:\s*['\"]?veracode/|pipeline-scan\.jar|VeracodeJavaAPI|srcclr|"
                          r"sca-downloads\.veracode\.com|veracode-cli", base, re.I))


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

def load_config(path: str | None) -> tuple[dict, list[tuple[str, dict]]]:
    if not path:
        return {}, []
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ToolError(f"cannot read config {path}: {exc}") from None
    if not isinstance(data, dict) or set(data) - {"defaults", "repos"}:
        raise ToolError("config must be a mapping with `defaults:` and/or `repos:`")
    defaults = data.get("defaults") or {}
    repos = data.get("repos") or {}
    if not isinstance(defaults, dict) or not isinstance(repos, dict):
        raise ToolError("config `defaults` and `repos` must be mappings")
    _check_keys(defaults, "defaults")
    overrides = []
    for pattern, values in repos.items():
        if not isinstance(values, dict):
            raise ToolError(f"config repos.{pattern} must be a mapping")
        _check_keys(values, f"repos.{pattern}")
        overrides.append((str(pattern), values))
    return defaults, overrides


def _check_keys(values: dict, where: str) -> None:
    unknown = set(values) - CONFIG_KEYS
    if unknown:
        raise ToolError(f"unknown config keys in {where}: {', '.join(sorted(unknown))}")
    if "artifact_path" in values and isinstance(values["artifact_path"], str):
        values["artifact_path"] = [values["artifact_path"]]
    for key, allowed in (("sast", {"auto", "on", "off"}), ("sca", {"auto", "on", "off"}),
                         ("iac", {"on", "artifacts", "off"})):
        if key in values:
            if values[key] is True or values[key] is False:
                values[key] = "on" if values[key] else "off"
            if values[key] not in allowed:
                raise ToolError(f"{where}.{key} must be one of {', '.join(sorted(allowed))}")


def effective_config(base: dict, overrides: list, cli: dict, repo: str | None) -> dict:
    cfg = dict(DEFAULTS)
    cfg.update(base)
    for pattern, values in overrides:
        if repo and fnmatch.fnmatch(repo.lower(), pattern.lower()):
            cfg.update(values)
    cfg.update({k: v for k, v in cli.items() if v is not None})
    return cfg


# --------------------------------------------------------------------------- #
# GitHub API
# --------------------------------------------------------------------------- #

class GitHubError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class GitHub:
    def __init__(self, token: str, api: str):
        self.token, self.api = token, api.rstrip("/")
        self.last_headers: dict = {}

    def request(self, method: str, path: str, body: dict | None = None, allow: tuple = ()):
        url = path if path.startswith("http") else f"{self.api}{path}"
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(4):
            req = urllib.request.Request(url, data=data, method=method, headers={
                "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": f"{TOOL}/{VERSION}",
                **({"Content-Type": "application/json"} if data else {})})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    self.last_headers = dict(resp.headers)
                    raw = resp.read()
                    return resp.status, (json.loads(raw) if raw else None)
            except urllib.error.HTTPError as exc:
                raw = exc.read()
                self.last_headers = dict(exc.headers or {})
                try:
                    payload = json.loads(raw) if raw else {}
                except ValueError:
                    payload = {"message": raw[:200].decode(errors="replace")}
                msg = payload.get("message", "") if isinstance(payload, dict) else ""
                limited = exc.code == 429 or (exc.code == 403 and "rate limit" in msg.lower())
                if (limited or exc.code >= 500) and attempt < 3:
                    wait = self.last_headers.get("Retry-After")
                    time.sleep(min(int(wait) if wait and wait.isdigit() else 2 ** (attempt + 1), 60))
                    continue
                if exc.code in allow:
                    return exc.code, payload
                raise GitHubError(exc.code, msg or "request failed") from None
            except urllib.error.URLError as exc:
                if attempt < 3:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise GitHubError(0, str(exc.reason)) from None
        raise GitHubError(0, "retries exhausted")  # pragma: no cover

    def get(self, path: str, allow404: bool = False):
        status, data = self.request("GET", path, allow=(404,) if allow404 else ())
        return None if status == 404 else data

    def paginate(self, path: str, key: str | None = None) -> list:
        sep = "&" if "?" in path else "?"
        out, page = [], 1
        while True:
            data = self.get(f"{path}{sep}per_page=100&page={page}")
            items = data.get(key, []) if key and isinstance(data, dict) else (data or [])
            out += items
            if len(items) < 100:
                return out
            page += 1


def resolve_token() -> str:
    for var in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        res = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        res = None
    if res and res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    raise ToolError("No GitHub token: set GH_TOKEN/GITHUB_TOKEN or run `gh auth login`.")


def q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def list_targets(gh: GitHub, targets: list[str], excludes: list[str], include_forks: bool,
                 login: str) -> list[dict]:
    repos: dict[str, dict] = {}
    for target in targets:
        target = target.strip().strip("/")
        if not target:
            continue
        owner, _, pattern = target.partition("/")
        pattern = pattern or "*"
        if any(c in owner for c in "*?["):
            raise ToolError(f"--target {target}: wildcards are only supported in the repo part")
        if not any(c in pattern for c in "*?["):
            repo = gh.get(f"/repos/{q(owner)}/{q(pattern)}", allow404=True)
            if repo is None:
                raise ToolError(f"--target {target}: repository not found or no access")
            candidates = [repo]
        else:
            if owner.lower() == login.lower():
                candidates = [r for r in gh.paginate("/user/repos?affiliation=owner")
                              if r["owner"]["login"].lower() == owner.lower()]
            else:
                status, _ = gh.request("GET", f"/orgs/{q(owner)}", allow=(404,))
                kind = "orgs" if status != 404 else "users"
                candidates = gh.paginate(f"/{kind}/{q(owner)}/repos?type=all" if kind == "orgs"
                                         else f"/users/{q(owner)}/repos?type=owner")
            candidates = [r for r in candidates if fnmatch.fnmatch(r["name"].lower(), pattern.lower())]
            candidates = [r for r in candidates if not r.get("archived") and not r.get("disabled")
                          and (include_forks or not r.get("fork"))]
        for r in candidates:
            full = r["full_name"]
            if any(fnmatch.fnmatch(full.lower(), e.lower()) for e in excludes):
                continue
            repos[full.lower()] = r
    return sorted(repos.values(), key=lambda r: r["full_name"].lower())


def read_file(gh: GitHub, full: str, path: str, ref: str) -> tuple[str, str] | None:
    data = gh.get(f"/repos/{full}/contents/{urllib.parse.quote(path)}?ref={q(ref)}", allow404=True)
    if not data or data.get("type") != "file":
        return None
    raw = base64.b64decode(data.get("content") or "")
    try:
        return raw.decode("utf-8"), data["sha"]
    except UnicodeDecodeError:
        return None


def branch_sha(gh: GitHub, full: str, branch: str) -> str | None:
    data = gh.get(f"/repos/{full}/git/ref/heads/{urllib.parse.quote(branch)}", allow404=True)
    return data["object"]["sha"] if isinstance(data, dict) and data.get("object") else None


def pin_actions(gh: GitHub) -> dict:
    pinned = {}
    for key, ref in ACTIONS.items():
        repo, tag = ref.split("@")
        data = gh.get(f"/repos/{repo}/commits/{q(tag)}")
        pinned[key] = f"{repo}@{data['sha']} # {tag}"
    return pinned


# --------------------------------------------------------------------------- #
# Pre-checks
# --------------------------------------------------------------------------- #

@dataclass
class Check:
    level: str   # PASS | WARN | FAIL | INFO
    name: str
    detail: str


def check_secrets(gh: GitHub, full: str, plan: Plan) -> tuple[list[Check], list[str]]:
    needed = list(SECRET_API) + ([SECRET_SCA] if plan.sca else [])
    names: set = set()
    readable = False
    for path in (f"/repos/{full}/actions/secrets", f"/repos/{full}/actions/organization-secrets"):
        try:
            names |= {s["name"] for s in gh.paginate(path, key="secrets")}
            readable = True
        except GitHubError as exc:
            # 422: user-owned repo (no org secrets).
            if exc.status not in (403, 404, 422):
                raise
    if not readable:
        return [Check("WARN", "secrets", "cannot list secrets (needs admin access); check them manually")], \
            [f"Make sure these Actions secrets exist: {', '.join(needed)} ({DOCS['creds']})"]
    missing = [n for n in needed if n not in names]
    if not missing:
        return [Check("PASS", "secrets", ", ".join(needed))], []
    todo = f"Add Actions secrets: {', '.join(missing)} (Settings > Secrets and variables > Actions)."
    if SECRET_SCA in missing:
        todo += f" SCA agent token: {DOCS['sca_agent']}"
    return [Check("WARN", "secrets", f"missing {', '.join(missing)}")], [todo]


def check_actions_policy(gh: GitHub, full: str) -> list[Check]:
    try:
        perms = gh.get(f"/repos/{full}/actions/permissions")
    except GitHubError as exc:
        if exc.status in (403, 404):
            return [Check("WARN", "actions policy", "cannot read Actions permissions; check manually")]
        raise
    if not perms.get("enabled", True):
        return [Check("FAIL", "actions policy", "GitHub Actions is disabled for this repository")]
    allowed = perms.get("allowed_actions", "all")
    if allowed == "all":
        return [Check("PASS", "actions policy", "all actions allowed")]
    if allowed == "local_only":
        return [Check("FAIL", "actions policy", "only local actions allowed; allow actions/* and veracode/*")]
    try:
        sel = gh.get(f"/repos/{full}/actions/permissions/selected-actions")
    except GitHubError:
        return [Check("WARN", "actions policy", "selected actions only; check actions/* and veracode/* are allowed")]
    patterns = [p.lower() for p in sel.get("patterns_allowed", [])]
    ok_veracode = any(fnmatch.fnmatch("veracode/veracode-sca@v1", p) or p.startswith("veracode/") for p in patterns)
    ok_github = sel.get("github_owned_allowed") or any(p.startswith("actions/") for p in patterns)
    if ok_veracode and ok_github:
        return [Check("PASS", "actions policy", "veracode/* and actions/* allowed")]
    return [Check("WARN", "actions policy", "selected actions only and veracode/* is not listed; "
                  "allow veracode/* (or the four Veracode actions)")]


# --------------------------------------------------------------------------- #
# Commit message
# --------------------------------------------------------------------------- #

def commit_message(plan: Plan, removing: bool = False) -> str:
    if removing:
        return f"Remove Veracode scans from {plan.workflow}\n\nRemoved by {TOOL}.\n"
    s = plan.summary
    lines = [f"Add Veracode scans to {plan.workflow}", "",
             f"Added by {TOOL} (community tool). Review the TODOs, then open a PR "
             "from this branch to test.", "", "Scans"]
    sast = {"off": "off", "binary": "build output", "source": "source code",
            "binary+source": "build output and source code"}[plan.sast_mode]
    r = plan.reasons
    lines.append(f"- SAST: {sast}" + (f", runs after job `{plan.needs}`" if plan.needs and plan.sast_mode != "off" else "")
                 + ("; Pipeline Scan on branch pushes and PRs, Policy Scan on the default branch" if plan.sast_mode != "off" else ""))
    if r.get("sast"):
        lines.append(f"  Why: {r['sast']}")
    lines.append(f"- SCA: {s['sca']} (agent-based)" + (f"\n  Why: {r['sca']}" if r.get("sca") else ""))
    if plan.sca_runner:
        lines.append(f"  Runner: {plan.sca_runner} ({r.get('runner', '')})")
    lines.append(f"- IaC/Secrets: {s['iac']}" + (f"\n  Why: {r['iac']}" if r.get("iac") else ""))
    if plan.todos:
        lines += ["", "TODO"] + [f"- {t}" for t in plan.todos]
    if plan.notes:
        lines += ["", "Notes"] + [f"- {n}" for n in plan.notes]
    lines += ["", f"Docs: {DOCS['tool']}#readme"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Runners
# --------------------------------------------------------------------------- #

@dataclass
class Result:
    repo: str
    outcome: str
    workflow: str = ""
    sast: str = ""
    sca: str = ""
    iac: str = ""
    detail: str = ""
    checks: list = field(default_factory=list)
    todos: list = field(default_factory=list)
    reasons: dict = field(default_factory=dict)
    decided: dict = field(default_factory=dict)
    url: str = ""


def choose_workflow(files: dict[str, str], det: Detection, cfg: dict, removing: bool = False,
                    force: bool = False) -> tuple[Workflow, list[str]]:
    """Pick the workflow to change. Returns (workflow, notes)."""
    parsed, notes = [], []
    for path, text in files.items():
        try:
            parsed.append(parse_workflow(path, text))
        except ToolError as exc:
            notes.append(f"ignored {exc}")
    if cfg.get("workflow"):
        want = cfg["workflow"]
        hits = [w for w in parsed if fnmatch.fnmatch(w.path, want) or fnmatch.fnmatch(w.path.rsplit("/", 1)[-1], want)]
        if len(hits) != 1:
            raise Skip(f"workflow '{want}' matched {len(hits)} files")
        return hits[0], notes
    managed = [w for w in parsed if BEGIN in w.text]
    if len(managed) == 1:
        return managed[0], notes
    if len(managed) > 1:
        raise Skip(f"managed blocks in several workflows: {', '.join(w.path for w in managed)}")
    if removing:
        raise Skip("nothing to remove: no managed Veracode blocks found")
    others = [w.path for w in parsed if has_other_veracode(w)]
    if others and not force:
        raise Skip(f"already runs Veracode in {', '.join(others)}; use --force to add the managed jobs anyway")
    cands = [w for w in parsed if w.triggers() & {"push", "pull_request"}]
    if not cands:
        raise Skip("no workflow triggered by push or pull_request")

    def rank(w: Workflow):
        stem = w.path.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
        has_build = bool([m for m in find_builds(w)])
        return (1 if DEPRIORITIZED_WF.search(stem) else 0,
                0 if (has_build or not det.compiled) else 1,
                0 if anchor_jobs(w) else 1,
                0 if {"push", "pull_request"} <= w.triggers() else 1,
                0 if stem in PREFERRED_WF else 1)
    cands.sort(key=rank)
    top = [w for w in cands if rank(w) == rank(cands[0])]
    if len(top) > 1:
        raise Skip(f"several candidate workflows ({', '.join(w.path for w in top)}); "
                   "set `workflow` in the config or --workflow")
    return cands[0], notes


def process_repo(gh: GitHub, repo: dict, cfg: dict, actions: dict, args) -> Result:
    full = repo["full_name"]
    res = Result(full, "skipped")
    default = repo.get("default_branch") or "main"
    branch = cfg["branch"]
    if branch == default:
        raise ToolError("--branch must differ from the default branch")
    on_branch = None if args.detect_only else branch_sha(gh, full, branch)
    ref = branch if on_branch else default  # workflow source: keeps edits made on the branch

    # Detection always reads the default branch: it holds the current code.
    status, tree = gh.request("GET", f"/repos/{full}/git/trees/{q(default)}?recursive=1", allow=(404, 409))
    if status in (404, 409):
        res.detail = "empty repository"
        return res
    blobs = [t for t in tree.get("tree", []) if t.get("type") == "blob"]
    paths = [t["path"] for t in blobs]
    sizes = {t["path"]: t.get("size") for t in blobs}
    linguist = gh.get(f"/repos/{full}/languages", allow404=True) or {}

    def read_project(path: str) -> str | None:
        got = read_file(gh, full, path, default)
        return got[0] if got else None

    det = detect(paths, linguist, bool(tree.get("truncated")), sizes, read_project, args.deep_dotnet)
    dec = scan_decisions(det, cfg)
    res.reasons = {k: v[1] for k, v in dec.items()}
    res.decided = {k: v[0] for k, v in dec.items()}
    if args.detect_only:
        res.outcome = "detected"
        return res

    listing = gh.get(f"/repos/{full}/contents/.github/workflows?ref={q(ref)}", allow404=True)
    if not isinstance(listing, list):
        res.detail = "no .github/workflows directory"
        return res
    files, shas = {}, {}
    for item in listing:
        if item.get("type") == "file" and item["name"].lower().endswith((".yml", ".yaml")):
            got = read_file(gh, full, item["path"], ref)
            if got:
                files[item["path"]], shas[item["path"]] = got
    if not files:
        res.detail = "no workflow files"
        return res
    if not args.remove and not (dec["sast"][0] or dec["sca"][0] or dec["iac"][0]):
        res.detail = "no scan applies to this repository"
        return res

    try:
        wf, notes = choose_workflow(files, det, cfg, args.remove, args.force)
        res.workflow = wf.path
        old = wf.text
        if args.remove:
            plan = Plan(wf.path)
            new = remove(old, args.force)
        else:
            plan = make_plan(wf, det, cfg)
            plan.notes = notes + plan.notes
            new = inject(old, plan, cfg, actions, args.force)
    except (Skip, ToolError) as exc:
        res.detail = str(exc)
        return res

    res.sast, res.sca, res.iac = (plan.summary["sast"], plan.summary["sca"], plan.summary["iac"]) \
        if not args.remove else ("", "", "")
    if not args.remove:
        sec_checks, sec_todos = check_secrets(gh, full, plan)
        plan.todos = sec_todos + plan.todos
        res.checks = [Check("PASS", "workflow", wf.path), *sec_checks, *check_actions_policy(gh, full)]
        if plan.build:
            res.checks.append(Check("PASS", "build", f"job `{plan.build.job}`, step \"{plan.build.label}\""))
        elif plan.sast_mode == "source":
            res.checks.append(Check("INFO", "build", "source-code SAST" + (f" after `{plan.needs}`" if plan.needs else "")))
        res.checks += [Check("INFO", "note", n) for n in plan.notes]
        res.checks.append(Check("INFO", "branch", f"{branch} {'exists, will update' if on_branch else 'will be created'}"))
        res.todos = plan.todos
    if any(c.level == "FAIL" for c in res.checks):
        res.detail = "; ".join(c.detail for c in res.checks if c.level == "FAIL")
        return res
    if new == old:
        res.outcome = "up_to_date"
        res.detail = "no changes needed"
        return res
    if args.dry_run:
        res.outcome = "would_change"
        if not args.no_diff:
            print(unified_diff(old, new, wf.path))
        return res

    if not on_branch:
        base_sha = branch_sha(gh, full, default)
        gh.request("POST", f"/repos/{full}/git/refs", {"ref": f"refs/heads/{branch}", "sha": base_sha})
    body = {"message": commit_message(plan, args.remove), "branch": branch,
            "content": base64.b64encode(new.encode("utf-8")).decode()}
    body["sha"] = shas[wf.path]
    _, data = gh.request("PUT", f"/repos/{full}/contents/{urllib.parse.quote(wf.path)}", body)
    res.outcome = "removed" if args.remove else "committed"
    res.url = f"{repo.get('html_url', '')}/tree/{branch}"
    res.detail = (data or {}).get("commit", {}).get("sha", "")[:12]
    return res


def run_targets(args, cli_cfg: dict) -> int:
    base_cfg, overrides = load_config(args.config)
    gh = GitHub(resolve_token(), os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    try:
        user = gh.get("/user")
    except GitHubError as exc:
        raise ToolError(f"GitHub authentication failed ({exc})") from None
    scopes = gh.last_headers.get("X-OAuth-Scopes") or gh.last_headers.get("x-oauth-scopes")
    if scopes is not None and not args.dry_run:
        have = {s.strip() for s in scopes.split(",")}
        if not {"repo", "workflow"} <= have and not ({"public_repo", "workflow"} <= have):
            raise ToolError(f"token scopes '{scopes}' cannot write workflow files; "
                            "needs repo + workflow (gh auth refresh -s workflow)")
    actions = pin_actions(gh) if args.pin_sha else dict(ACTIONS)
    repos = list_targets(gh, args.target, args.exclude, args.include_forks, user["login"])
    if not repos:
        print("No repositories matched the targets.")
        return 1
    results = []
    for repo in repos:
        cfg = effective_config(base_cfg, overrides, cli_cfg, repo["full_name"])
        try:
            res = process_repo(gh, repo, cfg, actions, args)
        except GitHubError as exc:
            res = Result(repo["full_name"], "failed", detail=str(exc))
        results.append(res)
        print_result(res, args.dry_run)
    print_summary(results)
    if args.report:
        write_report(args.report, results)
    return 0 if all(r.outcome in ("committed", "removed", "up_to_date", "would_change", "detected")
                    for r in results) else 1


def run_file(args, cli_cfg: dict) -> int:
    base_cfg, overrides = load_config(args.config)
    cfg = effective_config(base_cfg, overrides, cli_cfg, None)
    path = Path(args.file)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ToolError(f"cannot read {path}: {exc}") from None
    bom = raw.startswith(b"\xef\xbb\xbf")
    try:
        old = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ToolError(f"{path} is not UTF-8") from None
    rel = path.as_posix()
    if args.remove:
        plan, new = Plan(rel), remove(old, args.force)
    else:
        src = Path(args.source_dir) if args.source_dir else _repo_root(path)
        paths, sizes = walk_local(src)

        def read_project(p: str) -> str | None:
            try:
                return (src / p).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None

        det = detect(paths, None, False, sizes, read_project, args.deep_dotnet)
        print_decisions(scan_decisions(det, cfg), "")
        if args.detect_only:
            return 0
        wf = parse_workflow(rel, old)
        others = has_other_veracode(wf) and BEGIN not in old
        if others and not args.force:
            raise Skip("the workflow already runs Veracode; use --force to add the managed jobs anyway")
        plan = make_plan(wf, det, cfg)
        new = inject(old, plan, cfg, dict(ACTIONS), args.force)
        needed = list(SECRET_API) + ([SECRET_SCA] if plan.sca else [])
        plan.todos.insert(0, f"Make sure these Actions secrets exist: {', '.join(needed)} ({DOCS['creds']})")
        s = plan.summary
        print(f"Plan for {rel}: SAST {s['sast']} | SCA {s['sca']} | IaC {s['iac']}")
        for t in plan.todos:
            print(f"  TODO  {t}")
        for n in plan.notes:
            print(f"  note  {n}")
    if new == old:
        print("No changes needed.")
        return 0
    if args.dry_run:
        if not args.no_diff:
            print(unified_diff(old, new, rel))
        return 0
    out = Path(args.out) if args.out else path
    out.write_bytes((b"\xef\xbb\xbf" if bom else b"") + new.encode("utf-8"))
    print(f"Wrote {out}")
    if not args.remove:
        print("\nCommit message:\n" + commit_message(plan))
    return 0


def _repo_root(path: Path) -> Path:
    p = path.resolve().parent
    for cand in (p, *p.parents):
        if (cand / ".git").exists():
            return cand
        if cand.name == ".github":
            return cand.parent
    return Path.cwd()


def print_decisions(dec: dict, indent: str = "   ") -> None:
    for key, label in (("sast", "SAST"), ("sca", "SCA"), ("iac", "IaC")):
        on, why = dec[key]
        print(f"{indent}{label:<5} {'on ' if on else 'off'}  {why}")
    runner, why = dec["runner"]
    if runner:
        print(f"{indent}SCA runner: {runner} ({why})")


def print_result(res: Result, dry: bool) -> None:
    print(f"\n== {res.repo}: {res.outcome}" + (f" ({res.detail})" if res.detail else ""))
    if res.reasons:
        print_decisions({k: (res.decided[k], res.reasons[k]) for k in res.reasons})
    if res.workflow:
        print(f"   workflow: {res.workflow}" + (f" | SAST {res.sast} | SCA {res.sca} | IaC {res.iac}" if res.sast else ""))
    for c in res.checks:
        print(f"   {c.level:<4}  {c.name}: {c.detail}")
    for t in res.todos:
        print(f"   TODO  {t}")
    if res.url:
        print(f"   branch: {res.url}")


def print_summary(results: list[Result]) -> None:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    print("\nSummary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))


def write_report(path: str, results: list[Result]) -> None:
    def cell(v: str) -> str:
        v = str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "outcome", "workflow", "sast", "sca", "iac", "detail", "todos", "branch_url",
                    "sast_reason", "sca_reason", "iac_reason", "runner_reason"])
        for r in results:
            why, d = r.reasons, r.decided
            plan_or = (lambda k, v: v or ("on" if d.get(k) else "off" if d else ""))
            w.writerow([cell(x) for x in (r.repo, r.outcome, r.workflow, plan_or("sast", r.sast),
                                          plan_or("sca", r.sca), plan_or("iac", r.iac), r.detail,
                                          " | ".join(r.todos), r.url, why.get("sast", ""), why.get("sca", ""),
                                          why.get("iac", ""), why.get("runner", ""))])
    print(f"Report: {path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="veracode_inject.py",
        description="Add Veracode SAST, SCA and IaC/Secrets jobs to existing GitHub Actions workflows.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--target", action="append", metavar="TARGET",
                     help="org | org/repo | org/pattern* (repeatable, comma-separated)")
    src.add_argument("--file", metavar="PATH", help="local workflow file to change in place")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="skip org/repo matches (glob, repeatable)")
    p.add_argument("--include-forks", action="store_true", help="include forked repos in org/pattern targets")
    p.add_argument("--workflow", help="workflow file name or glob to change (default: auto-detect)")
    p.add_argument("--build-job", help="job id that builds the code")
    p.add_argument("--build-step", help="name or id of the build step inside --build-job")
    p.add_argument("--artifact-path", action="append", metavar="GLOB",
                   help="build output to scan (upload-artifact path line, repeatable)")
    p.add_argument("--branch", help=f"branch to commit to (default {DEFAULTS['branch']})")
    p.add_argument("--pr-gate-policy", help=f"policy for PR Pipeline Scans (default '{DEFAULTS['pr_gate_policy']}')")
    p.add_argument("--branch-fail-on-severity", help="severities that fail branch-push scans, e.g. 'Very High, High' (default: any flaw)")
    p.add_argument("--runner", help="runs-on for the Veracode jobs (default ubuntu-latest)")
    p.add_argument("--sast", choices=["auto", "on", "off"])
    p.add_argument("--sca", choices=["auto", "on", "off"])
    p.add_argument("--iac", choices=["on", "artifacts", "off"],
                   help="on: every repo (secret scanning); artifacts: only repos with IaC/container files")
    p.add_argument("--windows-runner", help="runs-on for SCA in Windows-only .NET/C++ repos (default windows-latest; 'off' keeps --runner)")
    p.add_argument("--deep-dotnet", action="store_true", help="read up to 5 .NET project files per repo to find Windows-only builds")
    p.add_argument("--detect-only", action="store_true", help="only report which scans apply; no workflow changes")
    p.add_argument("--sca-blocking", action="store_true", default=None, help="fail the run on SCA policy findings")
    p.add_argument("--iac-blocking", action="store_true", default=None, help="fail the run on IaC/Secrets findings")
    p.add_argument("--config", help="YAML config with defaults and per-repo overrides")
    p.add_argument("--pin-sha", action="store_true", help="pin actions to commit SHAs (targets only)")
    p.add_argument("--dry-run", action="store_true", help="run the pre-checks and show the diff, write nothing")
    p.add_argument("--no-diff", action="store_true", help="with --dry-run, do not print diffs")
    p.add_argument("--remove", action="store_true", help="remove the managed Veracode blocks")
    p.add_argument("--force", action="store_true", help="overwrite hand-edited managed blocks / add next to existing Veracode steps")
    p.add_argument("--report", metavar="CSV", help="write a CSV report (targets only)")
    p.add_argument("--source-dir", help="repo root for language detection (--file only; default: the file's repo)")
    p.add_argument("--out", help="write here instead of in place (--file only)")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.target:
        args.target = [t for item in args.target for t in item.split(",") if t.strip()]
    if args.build_step and not args.build_job:
        print("error: --build-step needs --build-job", file=sys.stderr)
        return 2
    cli_cfg = {
        "workflow": args.workflow, "build_job": args.build_job, "build_step": args.build_step,
        "artifact_path": args.artifact_path, "branch": args.branch, "pr_gate_policy": args.pr_gate_policy,
        "branch_fail_on_severity": args.branch_fail_on_severity, "runner": args.runner,
        "sast": args.sast, "sca": args.sca, "iac": args.iac, "windows_runner": args.windows_runner,
        "sca_blocking": args.sca_blocking, "iac_blocking": args.iac_blocking,
    }
    try:
        return run_targets(args, cli_cfg) if args.target else run_file(args, cli_cfg)
    except Skip as exc:
        print(f"skipped: {exc}", file=sys.stderr)
        return 1
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except GitHubError as exc:
        print(f"error: GitHub API {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
