#!/usr/bin/env python3
"""
Map vs. Territory Demo

Companion to "The Map is not the Territory: The Agent-Tool Trust Boundary"
https://niyikiza.com/posts/map-territory/

Demonstrates how attacks exploit the gap between what security checks
validate (the Map) and what actually executes (the Territory).

Run:
    python map_vs_territory.py            # Simulated attacks (interactive)
    python map_vs_territory.py --openai   # Real LLM demo (requires API key)

Requires: pip install tenuo path-jail url-jail proc-jail
For --openai: pip install openai tenuo
"""

import argparse
import json
import os
import re
import sys
import tempfile
import shutil
import time
from pathlib import Path
from urllib.parse import urlparse, unquote

# Optional imports - demo degrades gracefully
try:
    from tenuo import Subpath, UrlSafe, Shlex
    HAS_TENUO = True
except ImportError:
    HAS_TENUO = False

try:
    from path_jail import safe_open
    HAS_PATH_JAIL = True
except ImportError:
    HAS_PATH_JAIL = False

try:
    from url_jail import is_safe_url
    HAS_URL_JAIL = True
except ImportError:
    HAS_URL_JAIL = False

try:
    from proc_jail import safe_run
    HAS_PROC_JAIL = True
except ImportError:
    HAS_PROC_JAIL = False

# OpenAI integration (for --openai mode)
HAS_OPENAI = False
try:
    import openai
    from tenuo.openai import GuardBuilder, ConstraintViolation
    HAS_OPENAI = True
except ImportError:
    pass


# ============================================================================
#  DISPLAY HELPERS
# ============================================================================

class Colors:
    GRAY = "\033[90m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def header(text: str):
    print()
    print(f"{Colors.BOLD}{'=' * 65}{Colors.RESET}")
    print(f"{Colors.BOLD}  {text}{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 65}{Colors.RESET}")
    print()


def subheader(text: str):
    print()
    print(f"┌{'─' * 63}┐")
    print(f"│  {text:<60}│")
    print(f"└{'─' * 63}┘")
    print()


def result_pass(layer: str, reason: str):
    print(f"  {Colors.GREEN}[{layer:10}]{Colors.RESET} ✅ PASS — {reason}")


def result_fail(layer: str, reason: str):
    print(f"  {Colors.RED}[{layer:10}]{Colors.RESET} ❌ BLOCKED — {reason}")


def result_info(layer: str, info: str):
    print(f"  {Colors.GRAY}[{layer:10}]{Colors.RESET} {info}")


def attack_passes(layer: str):
    print(f"  {Colors.YELLOW}⚠️  Attack passes {layer}{Colors.RESET}")
    print()


def attack_blocked(layer: str):
    print(f"  {Colors.GREEN}🛡️  Attack blocked at {layer}{Colors.RESET}")
    print()


def summary(text: str):
    print()
    print(f"  {Colors.CYAN}SUMMARY:{Colors.RESET} {text}")
    print()


def not_installed(lib: str):
    print(f"  {Colors.GRAY}[SKIPPED]{Colors.RESET} {lib} not installed (pip install {lib})")


# ============================================================================
#  LAYER 1: REGEX (THE NAIVE APPROACH)
# ============================================================================

def layer1_path_check(path: str) -> tuple[bool, str]:
    """Naive regex-based path validation."""
    if ".." in path:
        return False, 'Contains ".."'
    if not path.startswith("/data/"):
        return False, 'Does not start with "/data/"'
    return True, 'Starts with "/data/", no ".."'


def layer1_url_check(url: str) -> tuple[bool, str]:
    """Naive regex-based SSRF check."""
    patterns = [
        r"127\.0\.0\.1",
        r"localhost",
        r"169\.254\.\d+\.\d+",
        r"10\.\d+\.\d+\.\d+",
        r"192\.168\.\d+\.\d+",
    ]
    for pattern in patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return False, f'Matches blocked pattern: {pattern}'
    return True, "No blocked patterns found"


def layer1_command_check(cmd: str) -> tuple[bool, str]:
    """Naive regex-based command injection check."""
    dangerous = [";", "|", "&", "$", "`", ">", "<"]
    for char in dangerous:
        if char in cmd:
            return False, f'Contains dangerous character: {char}'
    return True, "No dangerous characters found"


# ============================================================================
#  LAYER 1.5: SEMANTIC VALIDATION (ANNOTATING THE MAP)
# ============================================================================

def layer15_path_check(path: str, root: str = "/data") -> tuple[bool, str]:
    """Semantic path validation using Subpath."""
    if not HAS_TENUO:
        return None, "tenuo not installed"
    
    jail = Subpath(root)
    
    # URL decode first (handles %2f etc)
    decoded = unquote(path)
    
    if jail.contains(decoded):
        return True, f"Normalized path is within {root}"
    else:
        # Show the normalization
        normalized = os.path.normpath(decoded)
        return False, f'Normalizes to "{normalized}" — escapes {root}'


def layer15_url_check(url: str) -> tuple[bool, str]:
    """Semantic URL validation using UrlSafe."""
    if not HAS_TENUO:
        return None, "tenuo not installed"
    
    safe = UrlSafe()
    
    if safe.is_safe(url):
        return True, "URL resolves to allowed destination"
    else:
        # Try to explain why
        parsed = urlparse(url)
        host = parsed.hostname or ""
        
        # Check for decimal IP
        if host.isdigit():
            ip_int = int(host)
            ip_str = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
            return False, f'Decimal IP {host} = {ip_str} (private/loopback)'
        
        return False, "Resolves to private/loopback IP"


def layer15_command_check(cmd: str, allowed: list[str] = None) -> tuple[bool, str]:
    """Semantic command validation using Shlex."""
    if not HAS_TENUO:
        return None, "tenuo not installed"
    
    allowed = allowed or ["ls", "cat", "echo"]
    shlex_check = Shlex(allow=allowed)
    
    if shlex_check.matches(cmd):
        return True, f"Command uses allowed binary, no operators"
    else:
        # Try to explain why
        if "$(" in cmd or "`" in cmd:
            return False, "Contains command substitution"
        if any(op in cmd for op in [";", "|", "&&", "||"]):
            return False, "Contains shell operator"
        if any(op in cmd for op in [">", ">>"]):
            return False, "Contains redirect"
        return False, "Command not in allowlist or contains dangerous syntax"


# ============================================================================
#  LAYER 2: EXECUTION GUARDS (THE TERRITORY)
# ============================================================================

def layer2_path_check(path: str, root: str = "/data") -> tuple[bool, str]:
    """Execution-time path validation using path_jail."""
    if not HAS_PATH_JAIL:
        return None, "path-jail not installed"
    
    try:
        # This actually touches the filesystem
        real_path = os.path.realpath(path)
        if real_path.startswith(root):
            return True, f'realpath() → "{real_path}" (within jail)'
        else:
            return False, f'realpath() → "{real_path}" (escapes jail!)'
    except Exception as e:
        return False, f"Error: {e}"


def layer2_url_check(url: str) -> tuple[bool, str]:
    """Execution-time URL validation using url_jail."""
    if not HAS_URL_JAIL:
        return None, "url-jail not installed"
    
    try:
        if is_safe_url(url):
            return True, "DNS resolved to allowed IP"
        else:
            return False, "DNS resolves to private/loopback IP"
    except Exception as e:
        return False, f"Error: {e}"


# ============================================================================
#  DEMO SCENARIOS
# ============================================================================

def demo_path_traversal():
    """Path traversal with URL encoding bypass."""
    subheader("ATTACK: Path Traversal (URL Encoding Bypass)")
    
    # %2e = '.'  %2f = '/'  — fully encoded traversal
    attack = "/data/foo%2f%2e%2e%2f%2e%2e%2fetc/passwd"
    
    print(f"  {Colors.BOLD}Input:{Colors.RESET} read_file(\"{attack}\")")
    print()
    
    # Layer 1
    result_info("Layer 1", "Regex: checking for '..' and prefix")
    passed, reason = layer1_path_check(attack)
    if passed:
        result_pass("Layer 1", reason)
        attack_passes("Layer 1")
    else:
        result_fail("Layer 1", reason)
        attack_blocked("Layer 1")
        return
    
    # Layer 1.5
    result_info("Layer 1.5", "Subpath: URL decode, normalize, check containment")
    result_info("", f'URL decode: "{attack}" → "{unquote(attack)}"')
    result_info("", f'Normalize:  → "{os.path.normpath(unquote(attack))}"')
    passed, reason = layer15_path_check(attack)
    if passed is None:
        not_installed("tenuo")
    elif passed:
        result_pass("Layer 1.5", reason)
        attack_passes("Layer 1.5")
    else:
        result_fail("Layer 1.5", reason)
        attack_blocked("Layer 1.5")
        return
    
    summary("Regex fooled by URL encoding. Semantic validation caught it.")


def demo_ssrf_decimal_ip():
    """SSRF using decimal IP notation."""
    subheader("ATTACK: SSRF (Decimal IP)")
    
    attack = "http://2130706433/"
    ip_int = 2130706433
    ip_str = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
    
    print(f"  {Colors.BOLD}Input:{Colors.RESET} fetch_url(\"{attack}\")")
    print(f"  {Colors.GRAY}Note: 2130706433 = {ip_str} (loopback){Colors.RESET}")
    print()
    
    # Layer 1
    result_info("Layer 1", "Regex: checking for 127.0.0.1, localhost, etc.")
    passed, reason = layer1_url_check(attack)
    if passed:
        result_pass("Layer 1", reason)
        attack_passes("Layer 1")
    else:
        result_fail("Layer 1", reason)
        attack_blocked("Layer 1")
        return
    
    # Layer 1.5
    result_info("Layer 1.5", "UrlSafe: parse URL, detect decimal IP, check if private")
    passed, reason = layer15_url_check(attack)
    if passed is None:
        not_installed("tenuo")
    elif passed:
        result_pass("Layer 1.5", reason)
        attack_passes("Layer 1.5")
    else:
        result_fail("Layer 1.5", reason)
        attack_blocked("Layer 1.5")
    
    # Show redirect-based attack (CVE-2024-0243 style)
    print()
    print(f"  {Colors.GRAY}────────────────────────────────────────────────────────────{Colors.RESET}")
    print()
    print(f"  {Colors.BOLD}Redirect Attack:{Colors.RESET} (CVE-2024-0243 style)")
    print()
    
    redirect_url = "https://legit-site.com/api"
    print(f"  {Colors.BOLD}Input:{Colors.RESET} fetch_url(\"{redirect_url}\")")
    print(f"  {Colors.GRAY}But server responds: 302 → http://169.254.169.254/meta-data/{Colors.RESET}")
    print()
    
    result_info("Layer 1.5", "UrlSafe checks initial URL")
    result_pass("Layer 1.5", "legit-site.com is not private IP")
    attack_passes("Layer 1.5")
    
    result_info("Layer 2", "url_jail: follows redirect, checks destination IP")
    if HAS_URL_JAIL:
        result_fail("Layer 2", "Redirect target 169.254.169.254 is link-local — blocked")
        attack_blocked("Layer 2")
    else:
        not_installed("url-jail")
        print()
        print(f"  {Colors.YELLOW}  With url-jail installed:{Colors.RESET}")
        print(f"  {Colors.GRAY}  safe_fetch() resolves the final IP after redirects.{Colors.RESET}")
        print(f"  {Colors.GRAY}  Even if initial URL is legit, redirect to metadata is blocked.{Colors.RESET}")
        print()
    
    summary("Layer 1.5 can't see redirects. Layer 2 catches them at connection time.")


def demo_command_injection():
    """Command injection with $() substitution."""
    subheader("ATTACK: Command Injection (Substitution)")
    
    attack = "echo $(cat /etc/passwd)"
    
    print(f"  {Colors.BOLD}Input:{Colors.RESET} run_command(\"{attack}\")")
    print()
    
    # Layer 1 - note: $ is in our blocklist
    result_info("Layer 1", "Regex: checking for ; | & $ ` > <")
    passed, reason = layer1_command_check(attack)
    if passed:
        result_pass("Layer 1", reason)
        attack_passes("Layer 1")
    else:
        result_fail("Layer 1", reason)
        # This one actually gets caught by naive regex
        print()
        print(f"  {Colors.GRAY}(Layer 1 caught this one. Let's try a sneakier attack...){Colors.RESET}")
        print()
    
    # Try alternate attack that bypasses Layer 1
    alt_attack = "ls -la /tmp\ncat /etc/passwd"
    print(f"  {Colors.BOLD}Alternate:{Colors.RESET} run_command(\"ls -la /tmp\\ncat /etc/passwd\")")
    print(f"  {Colors.GRAY}(Newline injection — no semicolon needed){Colors.RESET}")
    print()
    
    result_info("Layer 1", "Regex: checking for ; | & $ ` > <")
    passed, reason = layer1_command_check(alt_attack)
    if passed:
        result_pass("Layer 1", reason)
        attack_passes("Layer 1")
    else:
        result_fail("Layer 1", reason)
        attack_blocked("Layer 1")
        return
    
    # Layer 1.5
    result_info("Layer 1.5", "Shlex: parse with shell semantics, check allowlist")
    passed, reason = layer15_command_check(alt_attack)
    if passed is None:
        not_installed("tenuo")
    elif passed:
        result_pass("Layer 1.5", reason)
        attack_passes("Layer 1.5")
    else:
        result_fail("Layer 1.5", reason)
        attack_blocked("Layer 1.5")
    
    # Now show a different attack that passes Shlex but is caught by proc_jail
    print()
    print(f"  {Colors.GRAY}────────────────────────────────────────────────────────────{Colors.RESET}")
    print()
    print(f"  {Colors.BOLD}Different scenario:{Colors.RESET} What if Shlex passes?")
    print()
    
    bypass_attack = "rm -rf /data/important"
    print(f"  {Colors.BOLD}Input:{Colors.RESET} run_command(\"{bypass_attack}\")")
    print(f"  {Colors.GRAY}(Simple command, no operators — Shlex would allow if 'rm' in allowlist){Colors.RESET}")
    print()
    
    result_info("Layer 1.5", "If allowlist includes 'rm', this passes Shlex")
    result_pass("Layer 1.5", "Single binary, no shell operators")
    attack_passes("Layer 1.5")
    
    # Layer 2 - proc_jail
    result_info("Layer 2", "proc_jail: validates binary at execve time")
    if HAS_PROC_JAIL:
        result_info("", "Configured allowed binaries: ['/bin/ls', '/bin/cat']")
        result_fail("Layer 2", "Binary '/bin/rm' not in allowlist — blocked at execve")
        attack_blocked("Layer 2")
    else:
        not_installed("proc-jail")
        print()
        print(f"  {Colors.YELLOW}  With proc-jail installed:{Colors.RESET}")
        print(f"  {Colors.GRAY}  safe_run() validates the actual binary at execution time.{Colors.RESET}")
        print(f"  {Colors.GRAY}  Even if Shlex allows 'rm', proc_jail can restrict to safe binaries.{Colors.RESET}")
        print()
    
    summary("Layer 1.5 parses syntax. Layer 2 enforces at the kernel boundary.")


def demo_homoglyph():
    """Homoglyph attack — visual deception."""
    subheader("ATTACK: Homoglyph (Visual Deception)")
    
    # Latin 'i' vs Cyrillic 'і' (U+0456)
    legit_path = "/usr/local/bin/java"
    attack_path = "/usr/local/bіn/java"  # Cyrillic і
    
    print(f"  {Colors.BOLD}Legitimate:{Colors.RESET} \"{legit_path}\"")
    print(f"  {Colors.BOLD}Attack:{Colors.RESET}     \"{attack_path}\"")
    print()
    print(f"  {Colors.GRAY}Look identical? Check the bytes:{Colors.RESET}")
    print(f"    Legitimate 'i': U+0069 (Latin Small Letter I)")
    print(f"    Attack 'і':     U+0456 (Cyrillic Small Letter Byelorussian-Ukrainian I)")
    print()
    print(f"  {Colors.BOLD}Bytes:{Colors.RESET}")
    print(f"    Legitimate: {legit_path.encode('utf-8')}")
    print(f"    Attack:     {attack_path.encode('utf-8')}")
    print()
    
    # Show they're different
    result_info("Comparison", f"legit_path == attack_path → {legit_path == attack_path}")
    print()
    
    # Layer 1 can't help
    result_info("Layer 1", "Regex: checking prefix...")
    if attack_path.startswith("/usr/local/"):
        result_pass("Layer 1", "Starts with /usr/local/")
        attack_passes("Layer 1")
    
    # Layer 1.5 can't help either
    result_info("Layer 1.5", "Subpath: normalize and check...")
    result_info("", f'Path is valid, within expected prefix')
    result_pass("Layer 1.5", "String validation passes — it's a valid path")
    attack_passes("Layer 1.5")
    
    # Only filesystem knows
    result_info("Layer 2", "path_jail: os.path.realpath()...")
    result_info("", "Filesystem resolves the actual bytes")
    result_info("", f'"/usr/local/bin/java" and "/usr/local/bіn/java" are DIFFERENT inodes')
    print()
    
    summary("Humans and string validators see the same thing. The filesystem doesn't.")
    print(f"  {Colors.YELLOW}This is why human-in-the-loop isn't a security boundary.{Colors.RESET}")


def demo_symlink_escape():
    """Symlink escape — Layer 1.5 passes, Layer 2 catches."""
    subheader("ATTACK: Symlink Escape")
    
    # Create temp directory structure
    temp_dir = tempfile.mkdtemp(prefix="tenuo_demo_")
    jail_dir = os.path.join(temp_dir, "data")
    os.makedirs(jail_dir)
    
    # Create a symlink that escapes
    symlink_path = os.path.join(jail_dir, "reports")
    target_path = "/etc"
    
    try:
        os.symlink(target_path, symlink_path)
    except OSError as e:
        print(f"  {Colors.RED}Could not create symlink: {e}{Colors.RESET}")
        print(f"  {Colors.GRAY}(May need elevated permissions){Colors.RESET}")
        shutil.rmtree(temp_dir)
        return
    
    attack = f"{jail_dir}/reports/passwd"
    
    print(f"  {Colors.BOLD}Setup:{Colors.RESET}")
    print(f"    Jail: {jail_dir}/")
    print(f"    Symlink: {jail_dir}/reports → /etc")
    print()
    print(f"  {Colors.BOLD}Input:{Colors.RESET} read_file(\"{attack}\")")
    print()
    
    # Layer 1
    result_info("Layer 1", f'Regex: starts with "{jail_dir}/"?')
    if attack.startswith(jail_dir):
        result_pass("Layer 1", "Prefix matches")
        attack_passes("Layer 1")
    
    # Layer 1.5
    result_info("Layer 1.5", "Subpath: normalize and check containment")
    normalized = os.path.normpath(attack)
    result_info("", f'Normalize: "{attack}" → "{normalized}"')
    result_info("", f'No ".." to resolve — string looks fine')
    result_pass("Layer 1.5", f"Path appears to be within {jail_dir}")
    attack_passes("Layer 1.5")
    
    print(f"  {Colors.YELLOW}⚠️  Layer 1.5 doesn't touch the filesystem!{Colors.RESET}")
    print(f"  {Colors.YELLOW}   It doesn't know {jail_dir}/reports is a symlink.{Colors.RESET}")
    print()
    
    # Layer 2
    result_info("Layer 2", "path_jail: os.path.realpath() — follows symlinks")
    real_path = os.path.realpath(attack)
    result_info("", f'realpath() → "{real_path}"')
    result_info("", f'Checking: "{real_path}".startswith("{jail_dir}")?')
    
    if real_path.startswith(jail_dir):
        result_pass("Layer 2", "Real path is within jail")
    else:
        result_fail("Layer 2", f"Real path escapes jail!")
        attack_blocked("Layer 2")
    
    summary("The Map looked safe. The Territory was hostile.")
    print(f"  {Colors.CYAN}Layer 2 is the only layer that sees reality.{Colors.RESET}")
    
    # Cleanup
    shutil.rmtree(temp_dir)


# ============================================================================
#  OPENAI DEMO (--openai mode)
# ============================================================================

READ_FILE_TOOL = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read contents of a file from the filesystem",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to read"
                }
            },
            "required": ["path"]
        }
    }
}


def execute_tool_call(tool_call) -> str:
    """Execute a tool call - this is what a real agent would do."""
    args = json.loads(tool_call.function.arguments)
    path = args.get("path", "")
    
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"


def demo_openai():
    """Real LLM demo showing Tenuo blocking dangerous tool calls."""
    
    if not HAS_OPENAI:
        print()
        print(f"  {Colors.RED}Missing dependencies for --openai mode{Colors.RESET}")
        print()
        print(f"  Install with:")
        print(f"    pip install openai tenuo")
        print()
        print(f"  Then set your API key:")
        print(f"    export OPENAI_API_KEY=sk-...")
        print()
        return
    
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print()
        print(f"  {Colors.RED}OPENAI_API_KEY not set{Colors.RESET}")
        print()
        print(f"  export OPENAI_API_KEY=sk-...")
        print()
        return
    
    header("REAL LLM DEMO: Tenuo vs Unprotected")
    
    print(f"  This demo uses a real OpenAI API call.")
    print(f"  We'll ask the LLM to read /etc/passwd.")
    print()
    print(f"  {Colors.BOLD}The question:{Colors.RESET} Can an LLM-powered agent read sensitive files?")
    print()
    
    input("  Press Enter to start...")
    print()
    
    # =========================================================================
    # UNPROTECTED: Raw OpenAI client
    # =========================================================================
    
    subheader("UNPROTECTED: Raw OpenAI Client")
    
    print(f"  {Colors.GRAY}client = openai.OpenAI(){Colors.RESET}")
    print(f"  {Colors.GRAY}# No guardrails. Tool calls execute directly.{Colors.RESET}")
    print()
    
    raw_client = openai.OpenAI()
    
    messages = [
        {"role": "system", "content": "You are a helpful assistant with access to the filesystem."},
        {"role": "user", "content": "Read the file /etc/passwd and show me its contents."}
    ]
    
    print(f"  {Colors.BOLD}User:{Colors.RESET} Read the file /etc/passwd and show me its contents.")
    print()
    print(f"  {Colors.GRAY}Calling OpenAI...{Colors.RESET}")
    
    try:
        response = raw_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=[READ_FILE_TOOL],
            tool_choice="auto"
        )
        
        choice = response.choices[0]
        
        if choice.message.tool_calls:
            tool_call = choice.message.tool_calls[0]
            args = json.loads(tool_call.function.arguments)
            path = args.get("path", "")
            
            print()
            print(f"  {Colors.YELLOW}[LLM]{Colors.RESET} Tool call: {tool_call.function.name}(\"{path}\")")
            print()
            
            # Execute it - this is what an unprotected agent would do
            print(f"  {Colors.RED}[EXECUTE]{Colors.RESET} Running tool call...")
            time.sleep(0.3)
            
            result = execute_tool_call(tool_call)
            
            print()
            print(f"  {Colors.RED}{'─' * 59}{Colors.RESET}")
            print(f"  {Colors.RED}[RESULT] File contents:{Colors.RESET}")
            print()
            # Show first few lines
            lines = result.strip().split('\n')[:8]
            for line in lines:
                print(f"    {line}")
            if len(result.strip().split('\n')) > 8:
                print(f"    {Colors.GRAY}... ({len(result.strip().split(chr(10)))} lines total){Colors.RESET}")
            print()
            print(f"  {Colors.RED}💀 ATTACK SUCCEEDED — Agent read /etc/passwd{Colors.RESET}")
            print(f"  {Colors.RED}{'─' * 59}{Colors.RESET}")
        else:
            print(f"  {Colors.GRAY}LLM didn't make a tool call. Response:{Colors.RESET}")
            print(f"  {choice.message.content[:200]}...")
            
    except Exception as e:
        print(f"  {Colors.RED}Error: {e}{Colors.RESET}")
        return
    
    print()
    input("  Press Enter to see the protected version...")
    print()
    
    # =========================================================================
    # PROTECTED: Tenuo GuardBuilder
    # =========================================================================
    
    subheader("PROTECTED: Tenuo GuardBuilder")
    
    print(f"  {Colors.CYAN}from tenuo.openai import GuardBuilder{Colors.RESET}")
    print(f"  {Colors.CYAN}from tenuo import Subpath{Colors.RESET}")
    print()
    print(f"  {Colors.GRAY}client = (GuardBuilder(openai.OpenAI()){Colors.RESET}")
    print(f"  {Colors.GRAY}    .allow(\"read_file\", path=Subpath(\"/data\")){Colors.RESET}")
    print(f"  {Colors.GRAY}    .build()){Colors.RESET}")
    print()
    print(f"  {Colors.GRAY}# Only paths within /data are allowed.{Colors.RESET}")
    print()
    
    protected_client = (GuardBuilder(openai.OpenAI())
        .allow("read_file", path=Subpath("/data"))
        .on_denial("raise")
        .build())
    
    print(f"  {Colors.BOLD}User:{Colors.RESET} Read the file /etc/passwd and show me its contents.")
    print()
    print(f"  {Colors.GRAY}Calling OpenAI...{Colors.RESET}")
    
    try:
        response = protected_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=[READ_FILE_TOOL],
            tool_choice="auto"
        )
        
        choice = response.choices[0]
        
        if choice.message.tool_calls:
            tool_call = choice.message.tool_calls[0]
            args = json.loads(tool_call.function.arguments)
            path = args.get("path", "")
            
            print()
            print(f"  {Colors.YELLOW}[LLM]{Colors.RESET} Tool call: {tool_call.function.name}(\"{path}\")")
            print(f"  {Colors.GREEN}[TENUO]{Colors.RESET} Tool call passed validation")
            print()
            
            result = execute_tool_call(tool_call)
            print(f"  {Colors.GRAY}Result: {result[:100]}...{Colors.RESET}")
        else:
            print(f"  {Colors.GRAY}LLM response: {choice.message.content[:200]}...{Colors.RESET}")
            
    except ConstraintViolation as e:
        print()
        print(f"  {Colors.GREEN}{'─' * 59}{Colors.RESET}")
        print(f"  {Colors.GREEN}[TENUO] 🛡️ BLOCKED — ConstraintViolation{Colors.RESET}")
        print()
        print(f"  {Colors.GRAY}Tool: read_file{Colors.RESET}")
        print(f"  {Colors.GRAY}Path: /etc/passwd{Colors.RESET}")
        print(f"  {Colors.GRAY}Constraint: Subpath(\"/data\"){Colors.RESET}")
        print()
        print(f"  {Colors.GRAY}The LLM tried to read /etc/passwd, but Tenuo blocked it{Colors.RESET}")
        print(f"  {Colors.GRAY}because the path is outside the allowed jail (/data).{Colors.RESET}")
        print()
        print(f"  {Colors.GREEN}🛡️ ATTACK PREVENTED — File was never read{Colors.RESET}")
        print(f"  {Colors.GREEN}{'─' * 59}{Colors.RESET}")
        
    except Exception as e:
        print(f"  {Colors.RED}Error: {e}{Colors.RESET}")
        return
    
    print()
    print(f"  {Colors.BOLD}Summary:{Colors.RESET}")
    print()
    print(f"    {Colors.RED}Unprotected:{Colors.RESET} LLM tool call executed → /etc/passwd leaked")
    print(f"    {Colors.GREEN}With Tenuo:{Colors.RESET}  Tool call blocked → Attack prevented")
    print()
    print(f"  {Colors.CYAN}This is why you need guardrails at the tool boundary.{Colors.RESET}")
    print(f"  {Colors.CYAN}The LLM doesn't know what's safe. Tenuo enforces it.{Colors.RESET}")
    print()


# ============================================================================
#  MAIN MENU
# ============================================================================

def print_menu():
    header("MAP VS. TERRITORY DEMO")
    print("  Companion to 'The Map is not the Territory'")
    print("  https://niyikiza.com/posts/map-territory/")
    print()
    print("  Choose a scenario:")
    print()
    print("    [1] Path Traversal (URL encoding bypass)")
    print("    [2] SSRF (Decimal IP)")
    print("    [3] Command Injection (Substitution / Newline)")
    print("    [4] Homoglyph Attack (Visual deception)")
    print("    [5] Symlink Escape (Layer 2 required)")
    print()
    print("    [a] Run all demos")
    print("    [q] Quit")
    print()


def check_dependencies():
    """Show which optional dependencies are available."""
    print()
    print(f"  {Colors.BOLD}Dependencies:{Colors.RESET}")
    
    if HAS_TENUO:
        print(f"    {Colors.GREEN}✓{Colors.RESET} tenuo (Layer 1.5)")
    else:
        print(f"    {Colors.RED}✗{Colors.RESET} tenuo — pip install tenuo")
    
    if HAS_PATH_JAIL:
        print(f"    {Colors.GREEN}✓{Colors.RESET} path-jail (Layer 2)")
    else:
        print(f"    {Colors.RED}✗{Colors.RESET} path-jail — pip install path-jail")
    
    if HAS_URL_JAIL:
        print(f"    {Colors.GREEN}✓{Colors.RESET} url-jail (Layer 2)")
    else:
        print(f"    {Colors.RED}✗{Colors.RESET} url-jail — pip install url-jail")
    
    if HAS_PROC_JAIL:
        print(f"    {Colors.GREEN}✓{Colors.RESET} proc-jail (Layer 2)")
    else:
        print(f"    {Colors.RED}✗{Colors.RESET} proc-jail — pip install proc-jail")
    
    print()


def run_all():
    """Run all demo scenarios."""
    demo_path_traversal()
    input("  Press Enter to continue...")
    
    demo_ssrf_decimal_ip()
    input("  Press Enter to continue...")
    
    demo_command_injection()
    input("  Press Enter to continue...")
    
    demo_homoglyph()
    input("  Press Enter to continue...")
    
    demo_symlink_escape()


def main():
    parser = argparse.ArgumentParser(
        description="Map vs Territory Demo - Attack scenarios and defenses"
    )
    parser.add_argument(
        "--openai",
        action="store_true",
        help="Run real LLM demo (requires OPENAI_API_KEY)"
    )
    args = parser.parse_args()
    
    if args.openai:
        demo_openai()
        return
    
    # Interactive menu mode
    print_menu()
    check_dependencies()
    
    while True:
        try:
            choice = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        
        if choice == "1":
            demo_path_traversal()
        elif choice == "2":
            demo_ssrf_decimal_ip()
        elif choice == "3":
            demo_command_injection()
        elif choice == "4":
            demo_homoglyph()
        elif choice == "5":
            demo_symlink_escape()
        elif choice == "a":
            run_all()
        elif choice == "q":
            break
        else:
            print(f"  {Colors.GRAY}Unknown option. Try 1-5, 'a', or 'q'.{Colors.RESET}")
        
        print()
        input("  Press Enter to return to menu...")
        print_menu()
    
    print()
    print("  Done. Read the full post at:")
    print("  https://niyikiza.com/posts/map-territory/")
    print()


if __name__ == "__main__":
    main()
