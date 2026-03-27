import subprocess
import platform
import os
import ctypes
import json
import logging
import re
import socket
import ssl
import datetime
import fnmatch
import urllib.request
import urllib.parse
import urllib.error
import concurrent.futures
import html as html_util
from html.parser import HTMLParser
from typing import Tuple
from mcp.server.fastmcp import FastMCP

try:
    from duckduckgo_search import DDGS
    _DDGS_AVAILABLE = True
except Exception:
    _DDGS_AVAILABLE = False

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("navy_server")

# --- Config ---
def _load_server_config():
    _dir = os.path.dirname(os.path.abspath(__file__))
    defaults = {
        "command_timeout": 120,
        "port_scan_timeout": 2,
        "port_scan_max_ports": 500,
        "port_scan_default_ports": "80,443,8080,22,21,25,3306,1433,3389,445,8443,8888,9200,6379,27017,5432,23,110,143,53",
        "fetch_url_timeout": 15,
        "fetch_url_max_chars": 8000,
        "read_file_max_chars": 50000,
        "search_timeout": 15,
        "search_max_results": 5,
        "system_specs_timeout": 15,
        "security_logs_timeout": 25,
        "security_logs_max_events": 30,
        "security_logs_max_output": 6000,
        "http_probe_timeout": 10,
        "file_list_max": 50,
        "ssl_check_timeout": 10,
        "subdomain_scan_timeout": 2,
        "subdomain_scan_workers": 40,
        "search_files_max": 100,
    }
    try:
        path = os.path.join(_dir, "config.json")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                overrides = json.load(f)
            if isinstance(overrides.get("server"), dict):
                for k, v in overrides["server"].items():
                    if k in defaults:
                        defaults[k] = v
    except Exception:
        pass
    env_map = {
        "NAVY_COMMAND_TIMEOUT": "command_timeout",
        "NAVY_PORT_SCAN_TIMEOUT": "port_scan_timeout",
        "NAVY_PORT_SCAN_MAX_PORTS": "port_scan_max_ports",
        "NAVY_PORT_SCAN_DEFAULT_PORTS": "port_scan_default_ports",
        "NAVY_FETCH_URL_TIMEOUT": "fetch_url_timeout",
        "NAVY_FETCH_URL_MAX_CHARS": "fetch_url_max_chars",
        "NAVY_READ_FILE_MAX_CHARS": "read_file_max_chars",
        "NAVY_SEARCH_TIMEOUT": "search_timeout",
        "NAVY_SEARCH_MAX_RESULTS": "search_max_results",
        "NAVY_SYSTEM_SPECS_TIMEOUT": "system_specs_timeout",
        "NAVY_SECURITY_LOGS_TIMEOUT": "security_logs_timeout",
        "NAVY_SECURITY_LOGS_MAX_EVENTS": "security_logs_max_events",
        "NAVY_SECURITY_LOGS_MAX_OUTPUT": "security_logs_max_output",
        "NAVY_HTTP_PROBE_TIMEOUT": "http_probe_timeout",
        "NAVY_FILE_LIST_MAX": "file_list_max",
    }
    for env_key, cfg_key in env_map.items():
        val = os.environ.get(env_key)
        if val is not None:
            try:
                if cfg_key not in ("port_scan_default_ports",):
                    defaults[cfg_key] = int(val)
                else:
                    defaults[cfg_key] = str(val).strip()
            except (ValueError, TypeError):
                pass
    return defaults

_config = _load_server_config()

mcp = FastMCP("Navy-System-Core")

class NavyState:
    def __init__(self):
        self.cwd = os.getcwd()

state = NavyState()

# --- UTILITIES ---

class SimpleHTMLParser(HTMLParser):
    _SKIP_TAGS = {"script", "style"}

    def __init__(self):
        super().__init__()
        self.text = []
        self._skip = False

    def handle_starttag(self, tag, _attrs):
        if tag.lower() in self._SKIP_TAGS:
            self._skip = True

    def handle_endtag(self, tag):
        if tag.lower() in self._SKIP_TAGS:
            self._skip = False

    def handle_data(self, data):
        if self._skip:
            return
        clean = data.strip()
        if clean:
            self.text.append(clean)

    def get_text(self):
        return " ".join(self.text)

def get_shell():
    if os.environ.get("PSModulePath"):
        return "PowerShell"
    return "CMD" if platform.system() == "Windows" else "Bash"

def is_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    else:
        try:
            return os.geteuid() == 0
        except (AttributeError, OSError):
            return False

def _resolve_path(path: str) -> Tuple[str, str]:
    base = os.path.abspath(state.cwd)
    full = os.path.abspath(os.path.join(state.cwd, path))
    if not (full == base or full.startswith(base + os.sep)):
        return full, "ERROR: Path must be inside current working directory."
    return full, ""

def _parse_ports(ports_str: str, max_ports: int) -> list:
    """Parse port spec supporting comma lists and ranges like '1-1024,8080,9000-9010'."""
    result = []
    for part in ports_str.replace(" ", "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
                result.extend(range(lo, min(hi + 1, 65536)))
            except ValueError:
                continue
        else:
            try:
                result.append(int(part))
            except ValueError:
                continue
    # Deduplicate, clamp, limit
    seen = set()
    clean = []
    for p in result:
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p)
            clean.append(p)
            if len(clean) >= max_ports:
                break
    return clean

def _unverified_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

# --- TOOLS ---

@mcp.tool()
def get_environment_metadata() -> str:
    """Returns detailed OS, Shell, Admin status, CWD, and file listing."""
    try:
        files = os.listdir(state.cwd)
        max_files = _config["file_list_max"]
        if len(files) > max_files:
            file_list = ", ".join(files[:max_files]) + f" ... (+{len(files)-max_files} more)"
        else:
            file_list = ", ".join(files)
    except Exception as e:
        file_list = f"Error listing files: {e}"

    info = {
        "os": f"{platform.system()} {platform.release()}",
        "shell": get_shell(),
        "is_admin": is_admin(),
        "cwd": state.cwd,
        "files_in_cwd": file_list,
    }
    return json.dumps(info)


@mcp.tool()
def get_system_specs() -> str:
    """Get GPU, RAM, CPU and disk info. Use when user asks 'is my PC good for gaming', 'system specs', or 'gaming assessment'."""
    try:
        if platform.system() != "Windows":
            try:
                with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                    cpu = f.read()
                cpu_line = next((l for l in cpu.splitlines() if "model name" in l.lower()), "")
                cpu_name = cpu_line.split(":", 1)[-1].strip() if cpu_line else "Unknown"
            except Exception:
                cpu_name = "Unknown"
            try:
                with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
                    mem = f.read()
                total = next((l for l in mem.splitlines() if l.startswith("MemTotal:")), "")
                total_kb = int(total.split()[1]) if total else 0
                ram_gb = round(total_kb / (1024 * 1024), 2)
            except Exception:
                ram_gb = 0
            return f"CPU: {cpu_name}\nRAM: {ram_gb} GB\n(GPU: run 'lspci | grep -i vga' for graphics)"
        ps = (
            "$gpu = (Get-CimInstance Win32_VideoController | Select-Object -First 1).Name; "
            "$cs = Get-CimInstance Win32_ComputerSystem; "
            "$ram = [math]::Round($cs.TotalPhysicalMemory/1GB, 2); "
            "$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1); "
            "$cpuName = $cpu.Name.Trim(); $cores = $cpu.NumberOfCores; $speed = $cpu.MaxClockSpeed; "
            "Write-Output \"GPU: $gpu\"; "
            "Write-Output \"RAM_GB: $ram\"; "
            "Write-Output \"CPU: $cpuName\"; "
            "Write-Output \"Cores: $cores MaxClockMHz: $speed\""
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True,
            timeout=_config["system_specs_timeout"], cwd=state.cwd,
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode != 0:
            return f"ERROR getting specs: {err or out or 'Unknown'}"
        return out
    except subprocess.TimeoutExpired:
        return "ERROR: get_system_specs timed out."
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def get_security_logs(max_events: int = 30) -> str:
    """Get recent Windows Security and Defender events. Use when user asks 'security logs', 'suspicious', 'defender', 'firewall logs'."""
    try:
        if platform.system() != "Windows":
            return "Security log tool is for Windows. On Linux use: journalctl -u systemd --no-pager -n 50, or check /var/log/auth.log."
        n = max(1, min(int(max_events) if max_events else _config["security_logs_max_events"], 50))
        ps = (
            "$out = @(); "
            "try { $sec = Get-WinEvent -LogName Security -MaxEvents " + str(n) + " -ErrorAction SilentlyContinue; "
            "foreach ($e in $sec) { $m = if ($e.Message) { $e.Message.Substring(0, [Math]::Min(120, $e.Message.Length)) } else { '' }; $out += \"[Security] Id=$($e.Id) $($e.TimeCreated) $m\" } } "
            "catch { $out += \"Security: $($_.Exception.Message) (run as admin for full log)\" }; "
            "try { $def = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 15 -ErrorAction SilentlyContinue; "
            "foreach ($e in $def) { $m = if ($e.Message) { $e.Message.Substring(0, [Math]::Min(100, $e.Message.Length)) } else { '' }; $out += \"[Defender] Id=$($e.Id) $($e.TimeCreated) $m\" } } "
            "catch { $out += \"Defender: $($_.Exception.Message)\" }; "
            "if ($out.Count -eq 0) { $out += 'No events. Run as Administrator for Security log.' }; $out -join \"`n\""
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True,
            timeout=_config["security_logs_timeout"], cwd=state.cwd,
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode != 0:
            return f"ERROR: {err or out or 'Unknown'}"
        return out[: _config["security_logs_max_output"]]
    except subprocess.TimeoutExpired:
        return "ERROR: get_security_logs timed out."
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Writes content to a file. Creates directories if needed. Path must be under current working directory."""
    try:
        full_path, err = _resolve_path(path)
        if err:
            return err
        parent = os.path.dirname(full_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(str(content))
        return f"SUCCESS: File written to {full_path}"
    except Exception as e:
        return f"ERROR writing file: {e}"


@mcp.tool()
def read_file(path: str) -> str:
    """Reads content from a LOCAL file. Path must be under current working directory. For web pages use fetch_url(url)."""
    try:
        full_path, err = _resolve_path(path)
        if err:
            return err
        if not os.path.exists(full_path):
            return "ERROR: File not found."
        limit = _config["read_file_max_chars"]
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read(limit + 1)
        except UnicodeDecodeError:
            with open(full_path, "r", encoding="latin-1", errors="replace") as f:
                content = f.read(limit + 1)
        if len(content) > limit:
            content = content[:limit] + "\n... (truncated)"
        return content
    except Exception as e:
        return f"ERROR reading file: {e}"


@mcp.tool()
def search_files(pattern: str, directory: str = ".", content: str = "") -> str:
    """Search for files by name glob pattern (e.g. '*.py', '*.log') and optionally by content string.
    directory: search root relative to CWD. content: if set, only return files containing this text (shows matching lines)."""
    try:
        search_root = os.path.abspath(os.path.join(state.cwd, directory))
        base = os.path.abspath(state.cwd)
        if not search_root.startswith(base):
            search_root = base

        name_pat = os.path.basename(pattern) if os.sep not in pattern and "/" not in pattern else pattern
        max_results = _config["search_files_max"]
        matches = []

        for root, dirs, files in os.walk(search_root):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", "node_modules", ".git")]
            for fname in files:
                if fnmatch.fnmatch(fname, name_pat):
                    fpath = os.path.join(root, fname)
                    rel = os.path.relpath(fpath, state.cwd)
                    if content:
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                text = f.read()
                            if content.lower() in text.lower():
                                hit_lines = [
                                    f"  L{i+1}: {ln.strip()[:80]}"
                                    for i, ln in enumerate(text.splitlines())
                                    if content.lower() in ln.lower()
                                ][:3]
                                matches.append(f"{rel}\n" + "\n".join(hit_lines))
                        except Exception:
                            pass
                    else:
                        size = os.path.getsize(fpath)
                        matches.append(f"{rel}  ({size} bytes)")
                    if len(matches) >= max_results:
                        break
            if len(matches) >= max_results:
                break

        if not matches:
            note = f" containing '{content}'" if content else ""
            return f"No files found matching '{pattern}'{note} in {directory}."
        header = f"Found {len(matches)} file(s) matching '{pattern}'" + (f" containing '{content}'" if content else "") + ":"
        return header + "\n" + "\n".join(matches)
    except Exception as e:
        return f"SEARCH ERROR: {e}"


def _search_web_scrape(query: str) -> str:
    url = "https://html.duckduckgo.com/html/"
    data = urllib.parse.urlencode({'q': query}).encode('utf-8')
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Referer': 'https://html.duckduckgo.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=_config["search_timeout"]) as response:
        raw = response.read().decode('utf-8', errors='replace')
    results = []
    seen_urls = set()

    legacy_links = re.findall(r'<a\s+class="result__a"\s+href="([^"]+)"[^>]*>([^<]+)</a>', raw, re.IGNORECASE | re.DOTALL)
    legacy_snippets = re.findall(r'<a\s+class="result__snippet"[^>]*>(.*?)</a>', raw, re.IGNORECASE | re.DOTALL)
    if legacy_links:
        for i, (link, title) in enumerate(legacy_links[:5]):
            if "duckduckgo.com" in link:
                try:
                    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
                    if 'uddg' in parsed:
                        link = urllib.parse.unquote(parsed['uddg'][0])
                except Exception:
                    continue
            title = html_util.unescape(re.sub(r'<[^>]+>', '', title)).strip()
            desc = legacy_snippets[i].strip() if i < len(legacy_snippets) else "No description."
            desc = html_util.unescape(re.sub(r'<[^>]+>', '', desc))[:300]
            results.append((link, title, desc or "No description."))
            seen_urls.add(link)

    if not results:
        for pattern in (r'<a\s+[^>]*href="(https://[^"]+)"[^>]*>([^<]+)</a>', r"<a\s+[^>]*href='(https://[^']+)'[^>]*>([^<]+)</a>"):
            direct_links = re.findall(pattern, raw)
            snippets = re.findall(r'class="[^"]*snippet[^"]*"[^>]*>([^<]+)<', raw)
            for href, title in direct_links:
                if "duckduckgo.com" in href or href in seen_urls:
                    continue
                title = html_util.unescape(re.sub(r'<[^>]+>', '', title)).strip()
                if len(title) < 3 or title.lower().startswith("http"):
                    continue
                if len(results) >= 5:
                    break
                desc = "No description."
                if len(results) < len(snippets):
                    desc = html_util.unescape(re.sub(r'<[^>]+>', '', snippets[len(results)])).strip()[:300]
                results.append((href, title[:200], desc))
                seen_urls.add(href)
            if results:
                break

    if not results:
        return "No results found."
    lines = []
    for i, (link, title, desc) in enumerate(results, 1):
        lines.append(f"[{i}] {title}\n    URL: {link}\n    Summary: {desc}\n")
    return "\n".join(lines)


@mcp.tool()
def search_web(query: str) -> str:
    """Searches the web using DuckDuckGo. Install duckduckgo-search for best results: pip install duckduckgo-search"""
    query = (query or "").strip()
    if not query:
        return "No search query provided."
    if _DDGS_AVAILABLE:
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ddgs = DDGS()
                items = list(ddgs.text(query, max_results=_config["search_max_results"]))
            if items:
                lines = []
                for i, item in enumerate(items, 1):
                    title = (item.get("title") or "").strip()
                    href = (item.get("href") or item.get("url") or "").strip()
                    body = (item.get("body") or "").strip()[:300]
                    if not href:
                        continue
                    lines.append(f"[{i}] {title}\n    URL: {href}\n    Summary: {body or 'No description.'}\n")
                if lines:
                    return "\n".join(lines)
        except Exception as e:
            log.debug("duckduckgo_search failed, using fallback: %s", e)
    try:
        return _search_web_scrape(query)
    except Exception as e:
        return f"SEARCH ERROR: {str(e)}"


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetches text content from a web URL. Use for URLs from search_web results. Do not use read_file for URLs."""
    try:
        if not url.startswith("http"):
            url = "https://" + url
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=_config["fetch_url_timeout"]) as response:
            html = response.read().decode('utf-8', errors='ignore')
            parser = SimpleHTMLParser()
            parser.feed(html)
            text = parser.get_text()
            text = re.sub(r'\s+', ' ', text).strip()
            return text[: _config["fetch_url_max_chars"]]
    except Exception as e:
        return f"WEB ERROR: {e}"


# --- Pentesting Tools (authorized targets only) ---

@mcp.tool()
def scan_ports(host: str, ports: str = None) -> str:
    """Scan a host for open TCP ports. Supports port ranges like '1-1024,8080,9000-9010'.
    Use only on targets you are authorized to test."""
    try:
        host = (host or "").strip()
        if not host:
            return "ERROR: host is required."
        default_ports = _config["port_scan_default_ports"]
        port_list = _parse_ports(ports or default_ports, _config["port_scan_max_ports"])
        if not port_list:
            return "ERROR: No valid ports specified."
        timeout = _config["port_scan_timeout"]

        def _check(port):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return port
            except (socket.timeout, socket.error, OSError):
                return None

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(port_list))) as ex:
            for result in ex.map(_check, port_list):
                if result is not None:
                    open_ports.append(result)

        if not open_ports:
            return f"Scan complete. No open ports found on {host} (checked {len(port_list)} ports)."
        return f"Open ports on {host}: {sorted(open_ports)}\n(Scanned {len(port_list)} ports)"
    except socket.gaierror as e:
        return f"ERROR: Could not resolve host '{host}': {e}"
    except Exception as e:
        return f"SCAN ERROR: {e}"


@mcp.tool()
def http_probe(url: str) -> str:
    """Get HTTP status and security headers for a URL (recon). Handles self-signed certs.
    Use only on targets you are authorized to test."""
    try:
        url = (url or "").strip()
        if not url:
            return "ERROR: url is required."
        if not url.startswith("http"):
            url = "http://" + url
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0 (Navy-Probe)"})
        # Try normal first, fall back to unverified for self-signed certs
        try:
            with urllib.request.urlopen(req, timeout=_config["http_probe_timeout"]) as response:
                status = response.getcode()
                headers = dict(response.headers)
                final_url = response.geturl()
        except urllib.error.URLError as ssl_err:
            if "certificate" in str(ssl_err).lower() or "ssl" in str(ssl_err).lower():
                with urllib.request.urlopen(req, timeout=_config["http_probe_timeout"], context=_unverified_ssl_ctx()) as response:
                    status = response.getcode()
                    headers = dict(response.headers)
                    final_url = response.geturl()
                headers["_ssl_note"] = "Self-signed/invalid cert (verified disabled)"
            else:
                raise
        security_headers = [
            "Server", "X-Powered-By", "X-AspNet-Version", "X-Frame-Options",
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
        ]
        lines = [f"Status: {status}", f"URL: {final_url}"]
        for h in security_headers:
            if h in headers:
                lines.append(f"{h}: {headers[h]}")
        for k, v in headers.items():
            if k not in security_headers and k.lower().startswith(("x-", "server")):
                lines.append(f"{k}: {v}")
        if "_ssl_note" in headers:
            lines.append(f"Note: {headers['_ssl_note']}")
        return "\n".join(lines)
    except urllib.error.HTTPError as e:
        lines = [f"Status: {e.code}", f"URL: {url}", f"Reason: {e.reason}"]
        for h in ["Server", "X-Powered-By", "X-Frame-Options"]:
            if h in e.headers:
                lines.append(f"{h}: {e.headers[h]}")
        return "\n".join(lines)
    except Exception as e:
        return f"PROBE ERROR: {e}"


@mcp.tool()
def dns_lookup(hostname: str) -> str:
    """Resolve hostname to IP addresses (A/AAAA). Use for recon on authorized targets only."""
    try:
        hostname = (hostname or "").strip()
        if not hostname:
            return "ERROR: hostname is required."
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = []
        for r in results:
            addr = r[4][0]
            if addr and addr not in ips:
                ips.append(addr)
        if not ips:
            return f"No addresses found for {hostname}."
        return f"{hostname} -> {', '.join(ips)}"
    except socket.gaierror as e:
        return f"DNS ERROR: {e}"
    except Exception as e:
        return f"LOOKUP ERROR: {e}"


@mcp.tool()
def ssl_check(host: str, port: int = 443) -> str:
    """Check SSL/TLS certificate for a host: validity, expiry, issuer, SANs, cipher, and protocol.
    Use only on targets you are authorized to test."""
    try:
        host = (host or "").strip()
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0]
        if not host:
            return "ERROR: host is required."

        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=_config["ssl_check_timeout"]) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as s:
                cert = s.getpeercert()
                cipher = s.cipher()
                protocol = s.version()

        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        try:
            expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
            expiry_str = f"{not_after}  ({days_left} days remaining)"
            expiry_warn = "  *** EXPIRES SOON ***" if days_left < 30 else ""
        except Exception:
            expiry_str = not_after
            expiry_warn = ""

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        lines = [
            f"Host:     {host}:{port}",
            f"Valid:    {not_before}  →  {expiry_str}{expiry_warn}",
            f"Subject:  CN={subject.get('commonName', 'N/A')}",
            f"Issuer:   {issuer.get('organizationName', 'N/A')} / {issuer.get('commonName', 'N/A')}",
            f"SANs:     {', '.join(sans[:15]) if sans else 'None'}",
            f"Cipher:   {cipher[0]}",
            f"Protocol: {protocol}",
        ]
        return "\n".join(lines)
    except ssl.SSLCertVerificationError as e:
        return f"SSL CERT INVALID: {e}"
    except ssl.SSLError as e:
        return f"SSL ERROR: {e}"
    except Exception as e:
        return f"SSL CHECK ERROR: {e}"


@mcp.tool()
def check_security_headers(url: str) -> str:
    """Grade a site's HTTP security headers on an A-F scale. Checks CSP, HSTS, X-Frame-Options, etc.
    Use only on targets you are authorized to test."""
    try:
        if not url.startswith("http"):
            url = "https://" + url
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Navy-Security-Check)"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw_headers = dict(resp.headers)
        except urllib.error.URLError:
            with urllib.request.urlopen(req, timeout=10, context=_unverified_ssl_ctx()) as resp:
                raw_headers = dict(resp.headers)
        headers = {k.lower(): v for k, v in raw_headers.items()}

        checks = [
            ("Content-Security-Policy",     "content-security-policy",     20, "Prevents XSS / injection attacks"),
            ("Strict-Transport-Security",   "strict-transport-security",   20, "Forces HTTPS connections"),
            ("X-Frame-Options",             "x-frame-options",             15, "Prevents clickjacking"),
            ("X-Content-Type-Options",      "x-content-type-options",      15, "Prevents MIME-type sniffing"),
            ("Referrer-Policy",             "referrer-policy",             10, "Controls referrer information"),
            ("Permissions-Policy",          "permissions-policy",          10, "Restricts browser feature access"),
            ("X-XSS-Protection",            "x-xss-protection",             5, "Legacy XSS browser filter"),
            ("Cache-Control",               "cache-control",                5, "Controls response caching"),
        ]
        max_score = sum(c[2] for c in checks)
        score = 0
        lines = [f"Security Header Report: {url}", ""]
        for name, key, points, desc in checks:
            val = headers.get(key)
            if val:
                lines.append(f"  PASS (+{points:2d})  {name}: {val[:80]}")
                score += points
            else:
                lines.append(f"  FAIL (  0)  {name}: MISSING  — {desc}")

        pct = int(score / max_score * 100)
        grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60 else "D" if pct >= 40 else "F"
        lines += ["", f"Score: {score}/{max_score} ({pct}%)  —  Grade: {grade}"]
        return "\n".join(lines)
    except Exception as e:
        return f"HEADER CHECK ERROR: {e}"


@mcp.tool()
def whois_lookup(domain: str) -> str:
    """Perform a WHOIS lookup for a domain or IP address."""
    try:
        domain = (domain or "").strip()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0]
        if not domain:
            return "ERROR: domain is required."

        # Try system whois on Linux/Mac
        if platform.system() != "Windows":
            try:
                proc = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
                out = proc.stdout.strip()
                if out and len(out) > 50:
                    key_fields = [l for l in out.splitlines() if any(
                        k in l.lower() for k in ["registrar", "creation", "expir", "updated",
                                                   "name server", "registrant", "status", "country", "refer"]
                    )]
                    return ("\n".join(key_fields[:25]) if key_fields else out[:2000]).strip()
            except Exception:
                pass

        # Fallback: raw WHOIS socket query via IANA
        def _whois_query(server: str, query: str) -> str:
            with socket.create_connection((server, 43), timeout=10) as s:
                s.sendall((query + "\r\n").encode())
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            return buf.decode("utf-8", errors="replace").strip()

        result = _whois_query("whois.iana.org", domain)
        # Follow refer: directive
        refer = next((l.split(":", 1)[1].strip() for l in result.splitlines() if l.lower().startswith("refer:")), None)
        if refer:
            result = _whois_query(refer, domain)

        if not result:
            return "No WHOIS data returned."
        # Extract key lines
        key_lines = [l for l in result.splitlines() if any(
            k in l.lower() for k in ["registrar", "creation", "expir", "updated",
                                       "name server", "registrant", "status", "country"]
        )]
        return ("\n".join(key_lines[:25]) if key_lines else result[:2000]).strip()
    except Exception as e:
        return f"WHOIS ERROR: {e}"


@mcp.tool()
def subdomain_scan(domain: str, extra_words: str = "") -> str:
    """Enumerate common subdomains via DNS resolution. Built-in wordlist + optional extra_words (comma-separated).
    Use only on domains you are authorized to test."""
    BUILTIN_WORDS = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
        "vpn", "api", "dev", "staging", "test", "beta", "admin", "portal",
        "app", "m", "mobile", "secure", "login", "auth", "cdn", "assets",
        "static", "media", "img", "images", "upload", "files", "download",
        "docs", "help", "support", "status", "monitor", "dashboard", "panel",
        "shop", "store", "blog", "news", "forum", "wiki", "git", "gitlab",
        "jenkins", "jira", "confluence", "exchange", "owa", "autodiscover",
        "ns1", "ns2", "ns3", "mx", "mx1", "mx2", "smtp1", "smtp2",
        "mail1", "mail2", "intranet", "internal", "corp", "office",
        "cloud", "backup", "db", "database", "redis", "elastic", "kibana",
        "grafana", "prometheus", "vault", "proxy", "gateway", "edge",
        "sandbox", "preprod", "uat", "qa", "demo", "old", "legacy",
    ]
    try:
        domain = (domain or "").strip()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0]
        if not domain:
            return "ERROR: domain is required."

        words = list(BUILTIN_WORDS)
        if extra_words:
            words += [w.strip() for w in extra_words.split(",") if w.strip()]
        words = list(dict.fromkeys(words))  # deduplicate preserving order

        def _check_sub(sub):
            fqdn = f"{sub}.{domain}"
            try:
                results = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                addrs = list({r[4][0] for r in results})
                return (fqdn, addrs)
            except socket.gaierror:
                return None

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=_config["subdomain_scan_workers"]) as ex:
            for result in ex.map(_check_sub, words):
                if result:
                    found.append(result)

        if not found:
            return f"No subdomains resolved for {domain} (checked {len(words)} names)."
        lines = [f"Found {len(found)} subdomain(s) for {domain} (checked {len(words)} names):"]
        for fqdn, ips in sorted(found, key=lambda x: x[0]):
            lines.append(f"  {fqdn}  ->  {', '.join(ips)}")
        return "\n".join(lines)
    except Exception as e:
        return f"SUBDOMAIN SCAN ERROR: {e}"


@mcp.tool()
def execute_command(json_command: str) -> str:
    """Executes system commands via shell."""
    try:
        if isinstance(json_command, dict):
            data = json_command
        else:
            try:
                data = json.loads(json_command)
            except (json.JSONDecodeError, TypeError):
                data = {"command": str(json_command), "args": []}

        cmd_raw = str(data.get("command", "")).strip()
        args = data.get("args", [])
        # Per-command timeout: AI can override the default by setting "timeout" in the JSON.
        # Capped at max_command_timeout from config (default 1800s).
        max_timeout = _config.get("max_command_timeout", 1800)
        try:
            cmd_timeout = int(data["timeout"]) if "timeout" in data else _config["command_timeout"]
            cmd_timeout = max(1, min(cmd_timeout, max_timeout))
        except (ValueError, TypeError):
            cmd_timeout = _config["command_timeout"]

        if not cmd_raw:
            if args:
                cmd_raw = str(args[0])
                args = args[1:]
            else:
                return "ERROR: Empty command provided."

        if cmd_raw.lower() in ["cd", "chdir"]:
            target = args[0] if args else "~"
            target = target.replace('"', '').replace("'", "")
            target = os.path.expanduser(target)
            new_path = os.path.abspath(os.path.join(state.cwd, str(target)))
            if os.path.exists(new_path) and os.path.isdir(new_path):
                state.cwd = new_path
                return f"SUCCESS: Directory changed to {state.cwd}"
            return f"ERROR: Directory {new_path} not found."

        if isinstance(args, list):
            safe_args = []
            for a in args:
                s_a = str(a).strip()
                if not s_a or s_a in ('"', "'"):
                    continue
                if " " in s_a and not (s_a.startswith('"') or s_a.startswith("'")):
                    safe_args.append(f'"{s_a}"')
                else:
                    safe_args.append(s_a)
            arg_str = " ".join(safe_args)
        else:
            arg_str = str(args).strip()
            if arg_str in ('"', "'"):
                arg_str = ""

        full_exec_str = f"{cmd_raw} {arg_str}".strip()
        final_call = full_exec_str

        if platform.system() == "Windows":
            _no_wrap = {"powershell", "pwsh", "wsl"}
            if cmd_raw.lower() not in _no_wrap and not any(x in cmd_raw.lower() for x in [".exe", ".bat", ".cmd"]):
                final_call = f"cmd /c {full_exec_str}"

        proc = subprocess.run(
            final_call,
            capture_output=True,
            shell=True,
            cwd=state.cwd,
            timeout=cmd_timeout,
            stdin=subprocess.DEVNULL,
        )

        try:
            stdout = proc.stdout.decode('utf-8', errors='replace').strip()
        except Exception:
            stdout = str(proc.stdout)
        try:
            stderr = proc.stderr.decode('utf-8', errors='replace').strip()
        except Exception:
            stderr = str(proc.stderr)

        output = ""
        if stdout:
            output += f"[STDOUT]\n{stdout}\n"
        if stderr:
            output += f"[STDERR]\n{stderr}\n"
        if not output:
            output = "Success (No Output)."
        if proc.returncode != 0:
            return f"EXIT CODE {proc.returncode}:\n{output}"
        return output.strip()

    except subprocess.TimeoutExpired:
        return f"ERROR: Command timed out ({cmd_timeout}s). Re-run with a higher timeout e.g. add \"timeout\": {cmd_timeout * 2} to the command JSON."
    except Exception as e:
        return f"CRITICAL EXECUTION ERROR: {str(e)}"


# --- Plugin Loader ---
# Drop .py files in a 'tools/' subdirectory. Each file should define register(mcp) to add tools.
_plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
if os.path.isdir(_plugins_dir):
    import importlib.util
    for _pfile in sorted(os.listdir(_plugins_dir)):
        if _pfile.endswith(".py") and not _pfile.startswith("_"):
            _ppath = os.path.join(_plugins_dir, _pfile)
            try:
                _spec = importlib.util.spec_from_file_location(f"navy_plugin_{_pfile[:-3]}", _ppath)
                _mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                if hasattr(_mod, "register"):
                    _mod.register(mcp)
                    log.info("Loaded plugin: %s", _pfile)
                else:
                    log.warning("Plugin %s has no register(mcp) function — skipped.", _pfile)
            except Exception as _pe:
                log.warning("Failed to load plugin %s: %s", _pfile, _pe)


if __name__ == "__main__":
    mcp.run()
