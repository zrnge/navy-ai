import asyncio
import json
import sys
import re
import argparse
import os
import warnings
import logging
import datetime

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("navy")

# --- Optional readline (command history) ---
try:
    import readline as _readline
    _HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".navy_history")
    try:
        _readline.read_history_file(_HISTORY_FILE)
    except FileNotFoundError:
        pass
    _readline.set_history_length(500)
    _READLINE = True
except ImportError:
    _READLINE = False
    _HISTORY_FILE = None

# --- AI Providers ---
try:
    import ollama
    OLLAMA_AVAILABLE = True
except Exception:
    OLLAMA_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except Exception:
    GEMINI_AVAILABLE = False

try:
    import openai as _openai_mod
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

try:
    import anthropic as _anthropic_mod
    ANTHROPIC_AVAILABLE = True
except Exception:
    ANTHROPIC_AVAILABLE = False

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.spinner import Spinner
from rich.markdown import Markdown
from rich.prompt import Confirm
from rich.table import Table

console = Console()


# --- Provider Detection ---
def _detect_provider(model: str) -> str:
    m = model.lower()
    # Ollama models always use "name:tag" format — check this first
    # to avoid misidentifying models like "gpt-oss:14b" as OpenAI
    if ":" in m:
        return "ollama"
    if "gemini" in m:
        return "gemini"
    # Only exact OpenAI model prefixes (not arbitrary strings containing "gpt")
    _openai_prefixes = ("gpt-3", "gpt-4", "o1-", "o1", "o3-", "o3", "o4-")
    if any(m == p or m.startswith(p) for p in _openai_prefixes):
        return "openai"
    if "claude" in m:
        return "anthropic"
    return "ollama"


# --- Context Manager ---
class ContextManager:
    """Manages conversation history with smart pruning."""
    def __init__(self, max_tokens=32000):
        self.history = []
        self.max_tokens = max_tokens
        self.char_limit = max_tokens * 4

    def add(self, role, content):
        self.history.append({"role": role, "content": str(content)})
        self._prune()

    def _prune(self):
        total = sum(len(m["content"]) for m in self.history)
        if total <= self.char_limit:
            return
        dropped = []
        while total > self.char_limit and len(self.history) > 2:
            msg = self.history.pop(0)
            dropped.append(msg)
            total -= len(msg["content"])
        if dropped:
            # Summarize what was dropped so context isn't lost silently
            user_snippets = [m["content"][:80] for m in dropped if m["role"] == "user"]
            note = f"[System: {len(dropped)} earlier messages trimmed. Earlier topics: {' | '.join(user_snippets[:3])}{'...' if len(user_snippets) > 3 else ''}]"
            self.history.insert(0, {"role": "user", "content": note})

    def get_history(self):
        return self.history

    def replace_history(self, history: list):
        self.history = list(history)


# --- Audit Logger ---
class AuditLogger:
    """Appends all commands, tool calls, and responses to a persistent audit log."""
    def __init__(self, path: str):
        self.path = path
        self.enabled = True
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(f"\n{'='*70}\nSession: {ts}\n{'='*70}")

    def _write(self, text: str):
        if not self.enabled:
            return
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception:
            pass

    def log_user(self, text: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._write(f"[{ts}] USER: {text}")

    def log_tool(self, tool: str, result: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._write(f"[{ts}] TOOL [{tool}]: {result[:800]}")

    def log_assistant(self, text: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._write(f"[{ts}] NAVY: {text[:800]}")


# --- Session Manager ---
class SessionManager:
    """Save, load, and list conversation sessions."""
    def __init__(self, sessions_dir: str):
        self.sessions_dir = sessions_dir
        os.makedirs(sessions_dir, exist_ok=True)

    def save(self, history: list, model: str, name: str = None) -> str:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^\w\-]", "_", name) if name else ts
        fname = f"session_{safe_name}.json"
        path = os.path.join(self.sessions_dir, fname)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"saved": ts, "model": model, "messages": history}, f, indent=2)
        return path

    def list_sessions(self) -> list:
        try:
            files = sorted(
                [f for f in os.listdir(self.sessions_dir) if f.endswith(".json")],
                reverse=True,
            )
        except FileNotFoundError:
            return []
        result = []
        for fname in files[:20]:
            path = os.path.join(self.sessions_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                result.append({
                    "file": fname,
                    "saved": data.get("saved", "?"),
                    "model": data.get("model", "?"),
                    "messages": len(data.get("messages", [])),
                })
            except Exception:
                result.append({"file": fname, "saved": "?", "model": "?", "messages": 0})
        return result

    def load(self, name: str) -> tuple:
        """Returns (history, model). Raises FileNotFoundError if not found."""
        try:
            candidates = os.listdir(self.sessions_dir)
        except FileNotFoundError:
            raise FileNotFoundError("No sessions found.")
        match = next(
            (f for f in candidates if f == name or f == name + ".json" or (name in f and f.endswith(".json"))),
            None,
        )
        if not match:
            raise FileNotFoundError(f"Session '{name}' not found.")
        path = os.path.join(self.sessions_dir, match)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("messages", []), data.get("model", "")

    def export_markdown(self, history: list, model: str, path: str):
        """Export conversation as a readable Markdown transcript."""
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [f"# Navy Session Transcript", f"**Exported:** {ts}  |  **Model:** {model}\n", "---\n"]
        for msg in history:
            role = msg.get("role", "?").upper()
            content = msg.get("content", "")
            if content.startswith("[System:"):
                continue
            lines.append(f"### {role}\n{content}\n")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


# --- CLI Config ---
def _load_models_config() -> dict:
    """Load models.json. Checks CWD first, then the script/package directory."""
    search_dirs = [os.getcwd(), os.path.dirname(os.path.abspath(__file__))]
    for d in search_dirs:
        path = os.path.join(d, "models.json")
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            log.warning("Could not load models.json from %s: %s", path, e)
    return {"default": "", "providers": {}, "presets": {}}


def _resolve_model_alias(name: str, models_cfg: dict) -> str:
    """Resolve a preset alias (e.g. 'flash') to a full model name. Returns name unchanged if not a preset."""
    presets = {k: v for k, v in models_cfg.get("presets", {}).items() if not k.startswith("_")}
    return presets.get(name, name)


def _cli_config():
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _cwd = os.getcwd()
    # Use CWD for runtime files so pip-installed users aren't writing into site-packages
    _runtime_dir = _cwd
    models_cfg = _load_models_config()
    default_model = models_cfg.get("default") or ""

    out = {
        "tool_output_truncate": 2000,
        "max_turns": 15,
        "default_ctx": 32768,
        "default_model": default_model,
        "audit_log": os.path.join(_runtime_dir, "navy_audit.log"),
        "sessions_dir": os.path.join(_runtime_dir, "navy_sessions"),
    }
    # Check CWD first for config.json, then script directory
    for _dir in (_cwd, _script_dir):
        path = os.path.join(_dir, "config.json")
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data.get("cli"), dict):
                    for k, v in data["cli"].items():
                        if k in out and v is not None:
                            if k in ("audit_log", "sessions_dir") and not os.path.isabs(str(v)):
                                out[k] = os.path.join(_dir, str(v))
                            else:
                                out[k] = v
                break  # stop at the first config.json found
        except Exception:
            pass
    for env_key, cfg_key in (
        ("NAVY_TOOL_TRUNCATE", "tool_output_truncate"),
        ("NAVY_MAX_TURNS", "max_turns"),
        ("NAVY_CTX", "default_ctx"),
    ):
        val = os.environ.get(env_key)
        if val is not None:
            try:
                out[cfg_key] = int(val)
            except ValueError:
                pass
    if os.environ.get("NAVY_DEFAULT_MODEL"):
        out["default_model"] = os.environ["NAVY_DEFAULT_MODEL"].strip()
    return out


# --- Main CLI ---
class NavyCLI:
    def __init__(self, model, ctx_size, skip_confirm=False):
        self.models_cfg = _load_models_config()
        # Resolve preset alias before anything else
        model = _resolve_model_alias(model, self.models_cfg)
        self.model = model
        self.ctx_size = ctx_size
        self.skip_confirm = skip_confirm
        self._cli_cfg = _cli_config()
        self.provider = _detect_provider(model)
        self._openai_client = None
        self._anthropic_client = None
        self.setup_provider()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        server_script = os.path.join(script_dir, "navy_server.py")
        if not os.path.isfile(server_script):
            raise FileNotFoundError(f"Navy server not found: {server_script}")
        self.server_params = StdioServerParameters(command=sys.executable, args=[server_script])
        self.memory = ContextManager(max_tokens=ctx_size)
        self.audit = AuditLogger(self._cli_cfg["audit_log"])
        self.sessions = SessionManager(self._cli_cfg["sessions_dir"])
        # In-memory transcript for /export
        self._transcript = []

    def _get_provider_key(self, provider: str) -> str:
        """Get API key: models.json providers section first, then environment variable."""
        p = self.models_cfg.get("providers", {}).get(provider, {})
        key = p.get("api_key", "").strip() if isinstance(p, dict) else ""
        if not key:
            env_var = (p.get("_api_key_env") if isinstance(p, dict) else None) or f"{provider.upper()}_API_KEY"
            key = os.environ.get(env_var, "").strip()
        return key

    def setup_provider(self):
        if self.provider == "gemini":
            if not GEMINI_AVAILABLE:
                raise RuntimeError("Gemini selected but 'google-generativeai' not installed. pip install google-generativeai")
            key = self._get_provider_key("gemini")
            if not key:
                raise RuntimeError("Gemini selected but no API key. Set api_key in models.json providers.gemini or set GEMINI_API_KEY env var.")
            try:
                genai.configure(api_key=key)
            except Exception as e:
                raise RuntimeError(f"Gemini config failed: {e}") from e

        elif self.provider == "openai":
            if not OPENAI_AVAILABLE:
                raise RuntimeError("OpenAI selected but 'openai' not installed. pip install openai")
            key = self._get_provider_key("openai")
            if not key:
                raise RuntimeError("OpenAI selected but no API key. Set api_key in models.json providers.openai or set OPENAI_API_KEY env var.")
            self._openai_client = _openai_mod.AsyncOpenAI(api_key=key)

        elif self.provider == "anthropic":
            if not ANTHROPIC_AVAILABLE:
                raise RuntimeError("Anthropic selected but 'anthropic' not installed. pip install anthropic")
            key = self._get_provider_key("anthropic")
            if not key:
                raise RuntimeError("Anthropic selected but no API key. Set api_key in models.json providers.anthropic or set ANTHROPIC_API_KEY env var.")
            self._anthropic_client = _anthropic_mod.Anthropic(api_key=key)

    def switch_model(self, new_model: str) -> bool:
        new_model = _resolve_model_alias(new_model.strip(), self.models_cfg)
        if not new_model:
            return False
        try:
            self.model = new_model
            self.provider = _detect_provider(new_model)
            self._openai_client = None
            self._anthropic_client = None
            self.setup_provider()
            return True
        except RuntimeError as e:
            console.print(f"[red]{e}[/]")
            return False

    async def call_ai(self, system_prompt, history):
        full_messages = [{"role": "system", "content": system_prompt}] + history
        full_text = ""

        try:
            # --- Gemini ---
            if self.provider == "gemini":
                model_obj = genai.GenerativeModel(self.model, system_instruction=system_prompt)
                hist_for_gemini = list(history)
                if hist_for_gemini and hist_for_gemini[-1]["role"] != "user":
                    hist_for_gemini.append({"role": "user", "content": "Continue."})
                gemini_hist = [
                    {"role": "user" if m["role"] == "user" else "model", "parts": [str(m["content"])]}
                    for m in hist_for_gemini
                ]
                gen_config = genai.types.GenerationConfig(temperature=0.2)

                def _gemini_stream():
                    buf = ""
                    for chunk in model_obj.generate_content(gemini_hist, stream=True, generation_config=gen_config):
                        try:
                            buf += chunk.text
                        except Exception:
                            pass
                    return buf

                with Live(Spinner("dots", text="Thinking...", style="cyan"), transient=True, console=console):
                    full_text = await asyncio.to_thread(_gemini_stream)

            # --- OpenAI ---
            elif self.provider == "openai":
                token_count = 0
                with Live(Spinner("dots", text="Generating...", style="cyan"), transient=True, console=console) as live:
                    async for chunk in await self._openai_client.chat.completions.create(
                        model=self.model,
                        messages=full_messages,
                        temperature=0.2,
                        stream=True,
                    ):
                        delta = chunk.choices[0].delta.content or ""
                        full_text += delta
                        token_count += 1
                        if token_count % 25 == 0:
                            live.update(Spinner("dots", text=f"Receiving... ({token_count} tokens)", style="cyan"))

            # --- Anthropic ---
            elif self.provider == "anthropic":
                # Anthropic needs system separate from messages
                anth_msgs = [m for m in full_messages if m["role"] != "system"]

                def _anthropic_stream():
                    buf = ""
                    with self._anthropic_client.messages.stream(
                        model=self.model,
                        max_tokens=8192,
                        system=system_prompt,
                        messages=anth_msgs,
                        temperature=0.2,
                    ) as stream:
                        for text in stream.text_stream:
                            buf += text
                    return buf

                with Live(Spinner("dots", text="Generating...", style="cyan"), transient=True, console=console):
                    full_text = await asyncio.to_thread(_anthropic_stream)

            # --- Ollama ---
            else:
                try:
                    ollama_client = ollama.AsyncClient()
                    token_count = 0
                    with Live(Spinner("dots", text="Generating...", style="cyan"), transient=True, console=console) as live:
                        async for chunk in await ollama_client.chat(
                            model=self.model,
                            messages=full_messages,
                            options={"num_ctx": self.ctx_size, "temperature": 0.2},
                            stream=True,
                        ):
                            full_text += chunk.message.content or ""
                            token_count += 1
                            if token_count % 20 == 0:
                                live.update(Spinner("dots", text=f"Receiving... ({token_count} tokens)", style="cyan"))
                except AttributeError:
                    with Live(Spinner("dots", text="Generating...", style="cyan"), transient=True, console=console):
                        resp = await asyncio.to_thread(
                            ollama.chat,
                            model=self.model,
                            messages=full_messages,
                            options={"num_ctx": self.ctx_size, "temperature": 0.2},
                        )
                    full_text = resp["message"]["content"]

        except Exception as e:
            return f"API ERROR: {e}"

        return full_text

    def _find_json_in_text(self, text):
        """Find first complete JSON object or array, respecting quoted strings."""
        for i, c in enumerate(text):
            if c not in "{[":
                continue
            open_char = c
            close_char = "}" if c == "{" else "]"
            depth = 1
            j = i + 1
            in_string = False
            escape_next = False
            while j < len(text) and depth > 0:
                ch = text[j]
                if escape_next:
                    escape_next = False
                elif ch == '\\' and in_string:
                    escape_next = True
                elif ch == '"':
                    in_string = not in_string
                elif not in_string:
                    if ch == open_char:
                        depth += 1
                    elif ch == close_char:
                        depth -= 1
                j += 1
            if depth == 0:
                return text[i:j]
        return None

    def _try_parse_json(self, candidate: str):
        """Try increasingly aggressive repairs to parse malformed JSON."""
        if not candidate:
            return None
        # Pass 1: direct
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        # Pass 2: Python literals
        fixed = candidate.replace("True", "true").replace("False", "false").replace("None", "null")
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
        # Pass 3: trailing commas
        fixed2 = re.sub(r",\s*([}\]])", r"\1", fixed)
        try:
            return json.loads(fixed2)
        except json.JSONDecodeError:
            pass
        # Pass 4: single-quoted keys/values (only if no double quotes)
        if '"' not in candidate:
            fixed3 = re.sub(r"'([^']*)'", r'"\1"', candidate)
            try:
                return json.loads(fixed3)
            except json.JSONDecodeError:
                pass
        # Pass 5: json5 if available
        try:
            import json5
            return json5.loads(candidate)
        except Exception:
            pass
        return None

    def extract_response(self, text):
        reasoning = None
        think_match = re.search(r'<thinking>(.*?)</thinking>', text, re.DOTALL | re.IGNORECASE)
        if think_match:
            reasoning = think_match.group(1).strip()
            text = text.replace(think_match.group(0), "")

        clean_text = re.sub(r'```json', '', text, flags=re.IGNORECASE).replace('```', '').strip()
        candidate = self._find_json_in_text(clean_text)
        json_data = self._try_parse_json(candidate) if candidate else None
        return reasoning, json_data, clean_text

    def normalize_action(self, data):
        if not data:
            return []
        if isinstance(data, list):
            steps = data
        elif isinstance(data, dict) and "sequence" in data:
            steps = data["sequence"]
        elif isinstance(data, dict):
            steps = [data]
        else:
            return []

        normalized = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            tool = step.get("tool", step.get("action"))
            if tool == "chat" or step.get("action") == "chat":
                normalized.append({"action": "chat", "message": step.get("message") or step.get("content") or ""})
                continue
            cmd = step.get("command")
            args = step.get("args", [])
            if isinstance(args, str):
                args = args.split()
            if tool == "execute_command":
                step["command"] = cmd
                step["args"] = args
            normalized.append(step)
        return normalized

    def _build_system_prompt(self, env_info: dict) -> str:
        _is_windows = "windows" in env_info.get("os", "").lower()
        _pentest_env_note = (
            "   - WSL KALI: WSL has NO -c flag. To run Kali tools: wsl -d kali-linux -- bash -c \"command here\". "
            "For nmap use IP/hostname only, NOT URLs (use 10.0.0.1 not http://10.0.0.1). Long scans may timeout at 120s.\n"
            if _is_windows else
            "   - LINUX PENTEST: You are already on Linux. Run tools DIRECTLY without any 'wsl' prefix "
            "(e.g. nmap 10.0.0.1, nikto -h http://10.0.0.1, gobuster dir -u ...). "
            "Use IP/hostname only for nmap, NOT URLs.\n"
        )
        return (
            f"SYSTEM STATUS:\n"
            f"- OS: {env_info.get('os')} | Shell: {env_info.get('shell')}\n"
            f"- CWD: {env_info.get('cwd')}\n"
            f"- FILES: {env_info.get('files_in_cwd')}\n\n"
            "### INSTRUCTIONS ###\n"
            "You are Navy, a powerful persistent CLI Agent. Be concise and action-oriented.\n"
            "1. MEMORY: You remember previous messages in the conversation.\n"
            "2. FORMAT: Output <thinking>...</thinking> THEN immediately output JSON (no prose between).\n"
            "   - STOP EARLY: As soon as a tool result answers the user's question, use {\"action\": \"chat\"} immediately. Do NOT run extra commands to verify or reconfirm what you already know.\n"
            "3. BASIC ACTIONS:\n"
            "   - {\"tool\": \"execute_command\", \"command\": \"...\", \"args\": [...]}\n"
            "   - {\"tool\": \"read_file\", \"path\": \"...\"}  (LOCAL files under CWD only)\n"
            "   - {\"tool\": \"fetch_url\", \"url\": \"...\"}  (web pages)\n"
            "   - {\"tool\": \"write_file\", \"path\": \"...\", \"content\": \"...\"}\n"
            "   - {\"tool\": \"search_web\", \"query\": \"...\"}\n"
            "   - {\"tool\": \"search_files\", \"pattern\": \"*.py\", \"directory\": \".\", \"content\": \"optional text to grep\"}\n"
            "   - {\"tool\": \"get_system_specs\"}  — GPU/RAM/CPU (no args)\n"
            "   - {\"tool\": \"get_security_logs\"}  — Windows Security/Defender events (no args)\n"
            "   - {\"action\": \"chat\", \"message\": \"...\"}  — for greetings, answers, summaries\n"
            "4. PENTEST TOOLS (authorized targets only):\n"
            "   - {\"tool\": \"scan_ports\", \"host\": \"...\", \"ports\": \"1-1024,8080\"}  — supports ranges\n"
            "   - {\"tool\": \"http_probe\", \"url\": \"...\"}  — HTTP status + security headers (handles self-signed certs)\n"
            "   - {\"tool\": \"dns_lookup\", \"hostname\": \"...\"}\n"
            "   - {\"tool\": \"ssl_check\", \"host\": \"...\", \"port\": 443}  — cert validity, expiry, cipher\n"
            "   - {\"tool\": \"check_security_headers\", \"url\": \"...\"}  — A-F grade for security headers\n"
            "   - {\"tool\": \"whois_lookup\", \"domain\": \"...\"}  — registrar, expiry, nameservers\n"
            "   - {\"tool\": \"subdomain_scan\", \"domain\": \"...\", \"extra_words\": \"word1,word2\"}  — DNS enumeration\n"
            "5. EXPERT KNOWLEDGE:\n"
            "   - COMPILATION: C/C++ on Windows with MinGW/Sockets: gcc file.c -o file.exe -lws2_32 -liphlpapi\n"
            "   - WINDOWS: Prefer PowerShell for OS info (Get-PSDrive, Get-CimInstance); wmic is deprecated.\n"
            "   - PENTEST WORKFLOW: scan_ports → http_probe → check_security_headers → ssl_check → subdomain_scan → whois_lookup.\n"
            "   - Do NOT use read_file for URLs; use fetch_url. Do NOT use wsl for native Linux tools.\n"
            + _pentest_env_note +
            "   - GAMING: When asked 'good for gaming?', call get_system_specs() first, then assess GPU/RAM/CPU.\n"
            "   - SECURITY LOGS: For 'suspicious activity', 'defender logs', call get_security_logs() first.\n"
            "   - FILE SEARCH: Use search_files to find files by name or content before read_file.\n"
        )


    async def _process_input(self, session, user_in: str, env_info: dict = None) -> dict:
        """Run the AI agent loop for a single user input. Returns updated env_info."""
        # --- Update env info ---
        try:
            res = await session.call_tool("get_environment_metadata", {})
            env_info = json.loads(res.content[0].text)
        except Exception as e:
            log.debug("Env metadata update failed: %s", e)
            if env_info is None:
                env_info = {}

        sys_prompt = self._build_system_prompt(env_info)
        self.memory.add("user", user_in)
        self.audit.log_user(user_in)

        max_turns = self._cli_cfg["max_turns"]
        turn = 0
        retry_count = 0
        last_cmd_hash = None

        while turn < max_turns:
            turn += 1
            try:
                ai_msg = await self.call_ai(sys_prompt, self.memory.get_history())
            except KeyboardInterrupt:
                console.print("[red]Aborted[/]")
                break
            if ai_msg.startswith("API ERROR:"):
                console.print(f"[bold red]{ai_msg}[/]")
                break

            reason, data, raw_text = self.extract_response(ai_msg)

            if reason:
                console.print(Panel(
                    Markdown(reason), title="[magenta]Thinking[/]",
                    border_style="magenta", expand=False,
                ))

            if not data:
                has_text = len(raw_text.strip()) > 0
                if not has_text and reason:
                    if retry_count < 2:
                        console.print("[dim yellow]...nudging agent for action...[/]")
                        self.memory.add("assistant", ai_msg)
                        self.memory.add("user", "System: Output the JSON action object now.")
                        retry_count += 1
                        continue
                    else:
                        console.print("[red]Agent stuck in planning loop. Try rephrasing.[/]")
                        break
                console.print(Panel(Markdown(ai_msg), title="[blue]Navy[/]", border_style="blue"))
                self.memory.add("assistant", ai_msg)
                self.audit.log_assistant(ai_msg)
                break

            steps = self.normalize_action(data)
            if not steps:
                break

            retry_count = 0
            task_completed = False
            tool_outputs = []

            for step in steps:
                action_type = step.get("action", "tool")

                # CHAT
                if action_type == "chat":
                    msg = (step.get("message") or step.get("content") or "").strip()
                    if not msg and reason:
                        msg = reason[:800] + ("..." if len(reason) > 800 else "")
                    if not msg:
                        msg = "See the output above, or ask again with more detail."
                    console.print(Panel(Markdown(msg), title="[blue]Navy[/]", border_style="blue"))
                    self.memory.add("assistant", msg)
                    self.audit.log_assistant(msg)
                    task_completed = True
                    break

                tool = step.get("tool")
                if not tool:
                    continue

                # Loop detection
                if tool == "execute_command":
                    current_hash = f"{step.get('command')}-{step.get('args')}"
                    if current_hash == last_cmd_hash:
                        console.print("[bold red]Loop detected: stopping repetitive command.[/]")
                        tool_outputs.append("System: You already ran this command. Stop and use 'chat' to report to the user.")
                        continue
                    last_cmd_hash = current_hash

                # Confirmations
                if not self.skip_confirm:
                    if tool == "execute_command":
                        cmd_display = step.get("command", "") + " " + " ".join(str(a) for a in step.get("args", []))
                        if not Confirm.ask(f"Run command? [dim]{cmd_display.strip()}[/]"):
                            tool_outputs.append("System: User declined execute_command.")
                            continue
                    elif tool == "write_file":
                        if not Confirm.ask(f"Write file [dim]{step.get('path', '?')}[/]?"):
                            tool_outputs.append("System: User declined write_file.")
                            continue
                    elif tool in ("scan_ports", "subdomain_scan"):
                        target = step.get("host") or step.get("domain") or "?"
                        if not Confirm.ask(f"[yellow]{tool}[/] on [dim]{target}[/]? (authorized targets only)"):
                            tool_outputs.append(f"System: User declined {tool}.")
                            continue
                    elif tool in ("http_probe", "ssl_check", "check_security_headers", "whois_lookup"):
                        target = step.get("url") or step.get("host") or step.get("domain") or "?"
                        if not Confirm.ask(f"[yellow]{tool}[/] on [dim]{target}[/]? (authorized only)"):
                            tool_outputs.append(f"System: User declined {tool}.")
                            continue

                console.print(f"[bold yellow]>> Executing: {tool}[/]")

                try:
                    if tool == "execute_command":
                        pl = {"command": step.get("command"), "args": step.get("args")}
                        if "timeout" in step:
                            pl["timeout"] = step["timeout"]
                        res = await session.call_tool("execute_command", {"json_command": json.dumps(pl)})

                    elif tool in [
                        "write_file", "read_file", "search_web", "fetch_url",
                        "scan_ports", "http_probe", "dns_lookup", "ssl_check",
                        "check_security_headers", "whois_lookup", "subdomain_scan",
                        "search_files", "get_system_specs", "get_security_logs",
                    ]:
                        tool_params = {k: v for k, v in step.items() if k not in ["tool", "action"]}
                        if "args" in tool_params and isinstance(tool_params["args"], list) and tool_params["args"]:
                            arg_list = tool_params.pop("args")
                            arg_map = {
                                "read_file": ("path",),
                                "search_web": ("query",),
                                "fetch_url": ("url",),
                                "scan_ports": ("host", "ports"),
                                "http_probe": ("url",),
                                "dns_lookup": ("hostname",),
                                "ssl_check": ("host", "port"),
                                "check_security_headers": ("url",),
                                "whois_lookup": ("domain",),
                                "subdomain_scan": ("domain", "extra_words"),
                                "search_files": ("pattern", "directory", "content"),
                            }
                            for idx, param_name in enumerate(arg_map.get(tool, ())):
                                if idx < len(arg_list) and param_name not in tool_params:
                                    tool_params[param_name] = str(arg_list[idx])
                        res = await session.call_tool(tool, tool_params)
                    else:
                        res = type("obj", (), {"content": [type("obj", (), {"text": f"Unknown tool: {tool}"})()]})()

                    result_text = res.content[0].text.strip()
                    is_error = "ERROR" in result_text or bool(re.search(r"EXIT CODE\s+[1-9]", result_text))
                    color = "red" if is_error else "green"
                    disp = result_text[:700] + "..." if len(result_text) > 700 else result_text
                    console.print(Panel(disp, title=f"Output: {tool}", border_style=color))
                    self.audit.log_tool(tool, result_text)

                    truncate = self._cli_cfg["tool_output_truncate"]
                    summary = result_text if len(result_text) <= truncate else result_text[:truncate] + "\n... (truncated)"
                    tool_outputs.append(f"Tool: {tool}\nResult: {summary}")

                except Exception as e:
                    err = f"System Error calling {tool}: {e}"
                    console.print(f"[red]{err}[/]")
                    tool_outputs.append(err)

            if task_completed:
                break
            if tool_outputs:
                combined = "System Notification: " + "\n".join(tool_outputs)
                limit = self._cli_cfg["tool_output_truncate"] * 2
                if len(combined) > limit:
                    combined = combined[:limit] + "\n... (output truncated)"
                self.memory.add("user", combined)
        else:
            console.print(f"[bold yellow]Max turns ({max_turns}) reached. Try rephrasing or breaking into smaller steps.[/]")
        return env_info

    async def main_loop(self):
        console.print(Panel.fit(
            f"[bold cyan]NAVY PRO[/bold cyan] [dim]v4.0[/dim]\n"
            f"[dim]Model: {self.model} ({self.provider})[/dim]\n"
            f"[dim]Audit: {self._cli_cfg['audit_log']}[/dim]\n"
            f"[dim]Config: config.json  |  Models: models.json[/dim]\n"
            f"[dim]Commands: /help  /models  model <alias>  /save  /load  /sessions  /export  /reset[/dim]",
            border_style="cyan",
        ))

        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                env_info = {}
                try:
                    res = await session.call_tool("get_environment_metadata", {})
                    env_info = json.loads(res.content[0].text)
                except Exception as e:
                    log.debug("Initial env metadata failed: %s", e)

                while True:
                    try:
                        cwd_display = env_info.get("cwd", ".")
                        user_in = console.input(f"\n[bold green]navy[/] [dim]in[/] [blue]{cwd_display}[/] > ").strip()
                    except KeyboardInterrupt:
                        console.print("")
                        continue
                    except EOFError:
                        break

                    if not user_in:
                        continue

                    # Save readline history
                    if _READLINE and _HISTORY_FILE:
                        try:
                            _readline.write_history_file(_HISTORY_FILE)
                        except Exception:
                            pass

                    if user_in.lower() in ["exit", "quit"]:
                        break
                    if user_in.lower() in ["cls", "clear"]:
                        console.clear()
                        continue

                    cmd = user_in.strip()

                    # --- Built-in commands ---
                    if cmd.lower() in ["/help", "help"]:
                        table = Table(title="Navy Commands", border_style="cyan", show_header=True)
                        table.add_column("Command", style="cyan")
                        table.add_column("Description")
                        table.add_row("model <name|alias>", "Switch AI model — use full name or alias from models.json")
                        table.add_row("/models", "List all model presets from models.json")
                        table.add_row("/reset", "Clear conversation memory")
                        table.add_row("/save [name]", "Save current session for later reload")
                        table.add_row("/sessions", "List saved sessions")
                        table.add_row("/load <name>", "Load a saved session")
                        table.add_row("/export [file]", "Export conversation as Markdown transcript")
                        table.add_row("clear / cls", "Clear terminal screen")
                        table.add_row("exit / quit", "Exit Navy")
                        console.print(table)
                        continue

                    # /models
                    if cmd.lower() == "/models":
                        presets = {k: v for k, v in self.models_cfg.get("presets", {}).items() if not k.startswith("_")}
                        default = self.models_cfg.get("default", "?")
                        table = Table(title="Model Presets  (models.json)", border_style="cyan")
                        table.add_column("Alias", style="cyan")
                        table.add_column("Full Model Name")
                        table.add_column("Provider")
                        for alias, full in sorted(presets.items()):
                            prov = _detect_provider(full)
                            marker = "  [green]← default[/]" if full == default else ""
                            table.add_row(alias, full + marker, prov)
                        console.print(table)
                        console.print(f"[dim]Current: [bold]{self.model}[/] ({self.provider})  |  Default: {default}[/]")
                        continue

                    if cmd.lower() in ["/reset", "reset"]:
                        self.memory = ContextManager(max_tokens=self.ctx_size)
                        self._transcript = []
                        console.print("[green]Conversation memory cleared.[/]")
                        continue

                    # /save [name]
                    if cmd.lower().startswith("/save"):
                        parts = cmd.split(None, 1)
                        name = parts[1].strip() if len(parts) > 1 else None
                        try:
                            path = self.sessions.save(self.memory.get_history(), self.model, name)
                            console.print(f"[green]Session saved to {path}[/]")
                        except Exception as e:
                            console.print(f"[red]Save failed: {e}[/]")
                        continue

                    # /sessions
                    if cmd.lower() == "/sessions":
                        sessions = self.sessions.list_sessions()
                        if not sessions:
                            console.print("[yellow]No saved sessions.[/]")
                        else:
                            table = Table(title="Saved Sessions", border_style="cyan")
                            table.add_column("File", style="cyan")
                            table.add_column("Saved")
                            table.add_column("Model")
                            table.add_column("Messages", justify="right")
                            for s in sessions:
                                table.add_row(s["file"], s["saved"], s["model"], str(s["messages"]))
                            console.print(table)
                        continue

                    # /load <name>
                    if cmd.lower().startswith("/load"):
                        parts = cmd.split(None, 1)
                        if len(parts) < 2:
                            console.print("[yellow]Usage: /load <session-name>[/]")
                            continue
                        try:
                            hist, loaded_model = self.sessions.load(parts[1].strip())
                            self.memory.replace_history(hist)
                            console.print(f"[green]Loaded session ({len(hist)} messages, model: {loaded_model or 'unknown'})[/]")
                        except FileNotFoundError as e:
                            console.print(f"[red]{e}[/]")
                        continue

                    # /export [filename]
                    if cmd.lower().startswith("/export"):
                        parts = cmd.split(None, 1)
                        fname = parts[1].strip() if len(parts) > 1 else f"navy_transcript_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                        try:
                            self.sessions.export_markdown(self.memory.get_history(), self.model, fname)
                            console.print(f"[green]Transcript exported to {fname}[/]")
                        except Exception as e:
                            console.print(f"[red]Export failed: {e}[/]")
                        continue

                    # model switch
                    if cmd.lower().startswith("model ") or cmd.lower().startswith("/model "):
                        new_name = cmd.split(None, 1)[1].strip() if " " in cmd else ""
                        if not new_name:
                            console.print("[yellow]Usage: model <name>  e.g.  model gpt-4o  or  model gemini-1.5-flash[/]")
                        elif self.switch_model(new_name):
                            console.print(f"[green]Model set to [bold]{self.model}[/] (provider: {self.provider})[/]")
                        continue

                    env_info = await self._process_input(session, user_in, env_info)


    async def run_once(self, query: str):
        """Single-shot mode: run one query and exit (no interactive loop)."""
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await self._process_input(session, query)


def cli_entry():
    """Entry point for the pip-installed `navy` command."""
    _cfg = _cli_config()
    _mcfg = _load_models_config()
    _default_model = (
        os.environ.get("NAVY_DEFAULT_MODEL")
        or _cfg["default_model"]
        or _mcfg.get("default", "")
    )
    parser = argparse.ArgumentParser(
        description="Navy - AI-powered CLI Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  navy                               interactive mode
  navy 'what is my IP?'              single-shot mode
  navy --model gpt-4o 'scan 10.0.0.1'
""",
    )
    parser.add_argument(
        "query", nargs="?", default=None,
        help="Run one query and exit (argument mode). Omit for interactive mode.",
    )
    parser.add_argument("--model", type=str, default=_default_model)
    parser.add_argument("--ctx", type=int, default=_cfg["default_ctx"])
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")
    args = parser.parse_args()

    if not args.model:
        console.print(
            "[red]No model configured.[/]\n"
            "[yellow]Option 1:[/] pass [cyan]--model <name>[/]  e.g.  [dim]navy --model qwen2.5:14b 'hi'[/]\n"
            "[yellow]Option 2:[/] create [cyan]models.json[/] in your current directory with a [dim]\"default\"[/] key.\n"
            "          Download the template: https://github.com/Zrnge/navy-ai/blob/master/models.json"
        )
        sys.exit(1)

    try:
        cli = NavyCLI(model=args.model, ctx_size=args.ctx, skip_confirm=args.yes)
        if args.query:
            asyncio.run(cli.run_once(args.query))
        else:
            asyncio.run(cli.main_loop())
    except KeyboardInterrupt:
        pass
    except (FileNotFoundError, RuntimeError) as e:
        console.print(f"[red]{e}[/]")
        import sys; sys.exit(1)


if __name__ == "__main__":
    cli_entry()
