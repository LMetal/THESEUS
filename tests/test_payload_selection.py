"""
Test standalone per il Payload Metadata Engine.
Zero dipendenze da agno/Metasploit — testa _parse_payload_name e _score_payload direttamente.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Replica minimal del motore da coder_tools.py ─────────────────────────────
_NATIVE_PLATFORMS = frozenset([
    "linux", "windows", "osx", "android", "bsd", "solaris", "aix", "irix",
])
_INTERPRETER_PLATFORMS = frozenset([
    "php", "python", "ruby", "java", "nodejs", "perl",
])
_KNOWN_ARCHES = frozenset([
    "x86", "x64", "x86_64", "arm", "arm64", "aarch64", "mips",
    "mipsle", "mipsbe", "ppc", "ppc64",
])
_SESSION_TYPES = frozenset([
    "meterpreter", "shell", "vncinject", "exec", "powershell",
])
_CONNECTION_ORDER = [
    "reverse_tcp", "reverse_http", "reverse_https",
    "bind_tcp", "reverse_sctp", "reverse_named_pipe",
    "reverse_ipv6_tcp", "reverse", "bind", "find_port",
    "interact", "",
]
_ARCH_NORM = {
    "x86_64": "x64", "amd64": "x64",
    "i386": "x86", "i686": "x86",
    "aarch64": "arm64",
}
_OS_PLATFORM = [
    ("linux",   ["linux", "debian", "ubuntu", "centos", "alpine", "fedora", "redhat", "unix"]),
    ("windows", ["windows", "win32", "win64", "microsoft", "ntlm"]),
    ("osx",     ["macos", "osx", "darwin", "apple"]),
    ("android", ["android"]),
    ("bsd",     ["bsd", "freebsd", "openbsd"]),
]


def _parse_payload_name(payload):
    parts = payload.lower().strip().split("/")
    result = {
        "platform": "generic", "arch": "",
        "session_type": "shell", "connection": "",
        "is_staged": False, "is_native": False, "is_interpreter": False,
    }
    if not parts or not parts[0]:
        return result
    platform = parts[0]
    result["platform"]       = platform
    result["is_native"]      = platform in _NATIVE_PLATFORMS
    result["is_interpreter"] = platform in _INTERPRETER_PLATFORMS
    remaining = parts[1:]

    def _extract_conn(s):
        for c in _CONNECTION_ORDER:
            if c and c in s:
                return c
        return ""

    if platform == "cmd":
        result["arch"]         = remaining[0] if remaining else ""
        result["connection"]   = remaining[1] if len(remaining) > 1 else ""
        result["session_type"] = "shell"
    elif platform == "generic":
        last = remaining[-1] if remaining else ""
        result["connection"]   = _extract_conn(last)
        if "meterpreter" in last:
            result["session_type"] = "meterpreter"
    elif platform in _INTERPRETER_PLATFORMS:
        if remaining and remaining[0] in _SESSION_TYPES:
            result["session_type"] = remaining[0]
            result["is_staged"]    = True
            result["connection"]   = remaining[1] if len(remaining) > 1 else ""
        elif remaining:
            last = remaining[-1]
            result["connection"]   = _extract_conn(last)
            result["session_type"] = "meterpreter" if "meterpreter" in last else "shell"
    else:
        if remaining and remaining[0] in _KNOWN_ARCHES:
            result["arch"] = remaining[0]
            remaining = remaining[1:]
        if remaining:
            if remaining[0] in _SESSION_TYPES:
                result["session_type"] = remaining[0]
                result["is_staged"]    = True
                result["connection"]   = remaining[1] if len(remaining) > 1 else ""
            else:
                last = remaining[-1]
                result["connection"] = _extract_conn(last)
                if "meterpreter" in last:
                    result["session_type"] = "meterpreter"
                elif "shell" in last or "powershell" in last:
                    result["session_type"] = "shell"
    result["arch"] = _ARCH_NORM.get(result["arch"], result["arch"])
    return result


def _resolve_target_platform(target_os):
    os_l = target_os.lower()
    for plat, kws in _OS_PLATFORM:
        if any(k in os_l for k in kws):
            return plat
    return ""


def _score_payload(payload, target_os, target_arch, prefer_meterpreter, all_compat):
    p = _parse_payload_name(payload)
    target_plat  = _resolve_target_platform(target_os)
    target_arch_n = _ARCH_NORM.get(target_arch.lower(), target_arch.lower())

    if p["platform"] == "generic":
        s_platform = 2
    elif p["platform"] == "cmd":
        has_binary = any(
            _parse_payload_name(q)["is_native"] or _parse_payload_name(q)["is_interpreter"]
            for q in all_compat
            if not q.startswith("cmd/") and not q.startswith("generic/")
        )
        s_platform = 3 if has_binary else 1
    elif p["is_interpreter"]:
        s_platform = 1
    elif p["is_native"]:
        if not target_plat:
            s_platform = 0
        elif p["platform"] == target_plat:
            s_platform = 0
        else:
            s_platform = 4
    else:
        s_platform = 2

    if not p["arch"] or not target_arch_n:
        s_arch = 2
    elif p["arch"] == target_arch_n:
        s_arch = 0
    elif p["arch"] == "x86" and target_arch_n == "x64":
        s_arch = 1
    else:
        s_arch = 3

    is_meter = "meterpreter" in p["session_type"]
    s_session = 0 if is_meter == prefer_meterpreter else 1

    try:
        s_conn = _CONNECTION_ORDER.index(p["connection"])
    except ValueError:
        s_conn = len(_CONNECTION_ORDER)

    s_staged = 1 if p["is_staged"] else 0

    return (s_platform, s_arch, s_session, s_conn, s_staged, payload.lower())


def smart_select(compat_payloads, target_os="", target_arch="", prefer_meterpreter=True):
    if not compat_payloads:
        return "generic/shell_reverse_tcp", []
    ranked = sorted(
        compat_payloads,
        key=lambda p: _score_payload(p, target_os, target_arch, prefer_meterpreter, compat_payloads),
    )
    return ranked[0], ranked[:5]


def simulate_with_fallback(compat_rpc, info_platform, info_arch, module_path, os_, arch, meter):
    """Simula fallback module.info per lista sospetta."""
    _suspicious = (
        not compat_rpc
        or (len(compat_rpc) <= 3 and all(p.startswith("cmd/unix") for p in compat_rpc))
    )
    compat = list(compat_rpc)
    if _suspicious:
        raw_p = info_platform.lower()
        raw_a = info_arch.lower()
        mod_platform = _resolve_target_platform(raw_p) or ("php" if "php" in raw_p else "")
        mod_arch     = _ARCH_NORM.get(raw_a, raw_a if raw_a in _KNOWN_ARCHES else "")
        if mod_platform and mod_platform not in ("php", "python"):
            archs = [mod_arch] if mod_arch else ["x64", "x86"]
            generated = []
            for a in archs:
                generated += [
                    f"{mod_platform}/{a}/meterpreter/reverse_tcp",
                    f"{mod_platform}/{a}/shell_reverse_tcp",
                    f"{mod_platform}/{a}/shell_bind_tcp",
                ]
            compat = generated + compat
        elif mod_platform == "php":
            compat = ["php/meterpreter/reverse_tcp", "php/shell_reverse_tcp"] + compat
    return smart_select(compat, os_, arch, meter) + (len(compat),)


# ── Parser unit tests ─────────────────────────────────────────────────────────
PARSER_TESTS = [
    ("linux/x86/meterpreter/reverse_tcp",
     {"platform":"linux","arch":"x86","session_type":"meterpreter","connection":"reverse_tcp","is_staged":True,"is_native":True}),
    ("linux/x64/shell_reverse_tcp",
     {"platform":"linux","arch":"x64","session_type":"shell","connection":"reverse_tcp","is_staged":False,"is_native":True}),
    ("cmd/unix/interact",
     {"platform":"cmd","arch":"unix","session_type":"shell","connection":"interact","is_staged":False,"is_native":False}),
    ("php/meterpreter/reverse_tcp",
     {"platform":"php","arch":"","session_type":"meterpreter","connection":"reverse_tcp","is_staged":True,"is_native":False}),
    ("generic/shell_reverse_tcp",
     {"platform":"generic","arch":"","session_type":"shell","connection":"reverse_tcp","is_staged":False,"is_native":False}),
    ("windows/x64/meterpreter/reverse_tcp",
     {"platform":"windows","arch":"x64","session_type":"meterpreter","connection":"reverse_tcp","is_staged":True,"is_native":True}),
    ("linux/x86/meterpreter/bind_tcp",
     {"platform":"linux","arch":"x86","session_type":"meterpreter","connection":"bind_tcp","is_staged":True,"is_native":True}),
    ("python/meterpreter/reverse_tcp",
     {"platform":"python","arch":"","session_type":"meterpreter","connection":"reverse_tcp","is_staged":True,"is_native":False}),
]

# ── Selection integration tests ───────────────────────────────────────────────
# (desc, compat_rpc, info_platform, info_arch, os, arch, prefer_meter, expected_prefix)
SELECTION_TESTS = [
    ("SambaCry is_known_pipename — solo cmd/unix da RPC, fallback linux/x86",
     ["cmd/unix/interact"],
     "Linux", "x86", "linux", "x86", True,
     "linux/x86/meterpreter"),

    ("Drupal Drupalgeddon2 — lista php reale",
     ["php/meterpreter/reverse_tcp", "php/shell_reverse_tcp", "generic/shell_reverse_tcp"],
     "php", "", "linux", "x64", True,
     "php/meterpreter"),

    ("Apache Struts2 — lista linux nativa",
     ["linux/x64/meterpreter/reverse_tcp", "linux/x86/meterpreter/reverse_tcp",
      "cmd/unix/reverse", "generic/shell_reverse_tcp"],
     "Linux", "x86_64", "linux", "x64", True,
     "linux/x64/meterpreter"),

    ("Shellshock CGI — no meterpreter, fallback linux/x86",
     ["cmd/unix/reverse", "cmd/unix/reverse_bash"],
     "Unix", "x86", "linux", "x86", False,
     "linux/x86/shell"),

    ("Samba usermap_script — solo cmd/unix, fallback linux/x86 con meterpreter",
     ["cmd/unix/reverse", "cmd/unix/reverse_bash"],
     "Linux", "x86", "linux", "x86", True,
     "linux/x86/meterpreter"),

    ("MS17-010 EternalBlue — lista windows nativa",
     ["windows/x64/meterpreter/reverse_tcp", "windows/meterpreter/reverse_tcp",
      "generic/shell_reverse_tcp"],
     "Windows", "x86_64", "windows", "x64", True,
     "windows/x64/meterpreter"),

    ("Modulo sconosciuto — lista vuota, fallback linux",
     [],
     "Linux", "x64", "linux", "x64", True,
     "linux/x64"),

    ("Nessun OS hint — lista mista, meterpreter preferred",
     ["linux/x86/meterpreter/reverse_tcp", "linux/x86/shell_reverse_tcp",
      "cmd/unix/reverse", "generic/shell_reverse_tcp"],
     "", "", "", "", True,
     "linux/x86/meterpreter"),

    ("Windows con shell non-meterpreter",
     ["windows/x64/meterpreter/reverse_tcp", "windows/x64/shell_reverse_tcp",
      "generic/shell_reverse_tcp"],
     "Windows", "x64", "windows", "x64", False,
     "windows/x64/shell"),
]


def run_parser_tests():
    passed = failed = 0
    print("\n  ── Parser tests ──────────────────────────────────────────────────────")
    for payload, expected in PARSER_TESTS:
        result = _parse_payload_name(payload)
        ok = all(result.get(k) == v for k, v in expected.items())
        icon = "✅" if ok else "❌"
        print(f"  {icon} {payload}")
        if not ok:
            for k, v in expected.items():
                if result.get(k) != v:
                    print(f"       {k}: expected={v!r}  got={result.get(k)!r}")
        if ok: passed += 1
        else:  failed += 1
    print(f"\n  Parser: {passed}/{passed+failed} passed")
    return failed == 0


def run_selection_tests():
    passed = failed = 0
    print("\n  ── Selection tests ───────────────────────────────────────────────────")
    print(f"  {'Test Case':<50} {'Suggested Payload':<40} {'N':>4}  Result")
    print("  " + "─" * 108)
    for desc, compat, ip, ia, os_, arch, meter, expected in SELECTION_TESTS:
        try:
            payload, top, n = simulate_with_fallback(compat, ip, ia, "", os_, arch, meter)
            ok = payload.startswith(expected)
            icon = "✅" if ok else "❌"
            status = "PASS" if ok else f"FAIL  (expected prefix: {expected})"
            print(f"  {icon} {desc:<49} {payload:<40} {n:>4}  {status}")
            if not ok:
                print(f"       top: {top}")
            if ok: passed += 1
            else:  failed += 1
        except Exception as e:
            failed += 1
            print(f"  ❌ {desc:<49} EXCEPTION: {e}")
    print("  " + "─" * 108)
    print(f"\n  Selection: {passed}/{passed+failed} passed\n")
    return failed == 0


if __name__ == "__main__":
    p1 = run_parser_tests()
    p2 = run_selection_tests()
    sys.exit(0 if (p1 and p2) else 1)
