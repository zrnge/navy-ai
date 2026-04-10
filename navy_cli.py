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
from rich.table import Table
from rich.rule import Rule
from rich.text import Text

console = Console()

_TOOL_ICONS = {
    "execute_command":        "💻",
    "read_file":              "📄",
    "write_file":             "📝",
    "search_files":           "🔍",
    "fetch_url":              "🌐",
    "search_web":             "🔎",
    "scan_ports":             "🛰 ",
    "http_probe":             "🌐",
    "ssl_check":              "🔒",
    "check_security_headers": "🛡 ",
    "dns_lookup":             "📡",
    "whois_lookup":           "📋",
    "subdomain_scan":         "🗺 ",
    "get_system_specs":       "🖥 ",
    "get_security_logs":      "📜",
}


# ---- Arrow-key Yes/No picker ----
def _confirm_arrow(label: str, default: bool = True) -> bool:
    """Yes/No confirmation with ← → arrow keys. Falls back to y/n if not a TTY."""
    import sys as _sys
    if not _sys.stdin.isatty():
        return default
    sel = [1 if default else 0]  # list so closure can mutate; 0=No 1=Yes

    def _draw():
        no_str  = "\033[1;31m◀ No \033[0m" if sel[0] == 0 else "\033[2m  No \033[0m"
        yes_str = "\033[1;32m Yes ▶\033[0m" if sel[0] == 1 else "\033[2m Yes  \033[0m"
        _sys.stdout.write(f"\r  {label}   {no_str}   {yes_str}  ")
        _sys.stdout.flush()

    _sys.stdout.write("\n")
    _draw()

    try:
        if _sys.platform == "win32":
            import msvcrt
            while True:
                ch = msvcrt.getwch()
                if ch in ('\x00', '\xe0'):
                    arrow = msvcrt.getwch()
                    if arrow == 'K':    sel[0] = 0; _draw()
                    elif arrow == 'M':  sel[0] = 1; _draw()
                elif ch in ('\r', '\n'):
                    _sys.stdout.write("\n"); return sel[0] == 1
                elif ch.lower() == 'y': _sys.stdout.write("\n"); return True
                elif ch.lower() == 'n': _sys.stdout.write("\n"); return False
                elif ch == '\x03':      _sys.stdout.write("\n"); raise KeyboardInterrupt
        else:
            import tty as _tty, termios as _termios
            fd = _sys.stdin.fileno()
            old = _termios.tcgetattr(fd)
            try:
                _tty.setraw(fd)
                while True:
                    ch = _sys.stdin.read(1)
                    if ch == '\x1b':
                        seq = _sys.stdin.read(2)
                        if seq == '[D':   sel[0] = 0; _draw()
                        elif seq == '[C': sel[0] = 1; _draw()
                    elif ch in ('\r', '\n'): return sel[0] == 1
                    elif ch.lower() == 'y': return True
                    elif ch.lower() == 'n': return False
                    elif ch == '\x03':      raise KeyboardInterrupt
            finally:
                _termios.tcsetattr(fd, _termios.TCSADRAIN, old)
                _sys.stdout.write("\n"); _sys.stdout.flush()
    except Exception:
        # Any terminal error — fall back to default
        return default


# ---- Simple query detection ----
_SIMPLE_PREFIXES = (
    "what is ", "what's ", "what are ", "who is ", "who are ",
    "how does ", "how do ", "how is ", "why is ", "why does ",
    "when is ", "when did ", "where is ", "tell me about ",
    "explain ", "define ", "describe ", "what does ",
    "can you explain", "do you know", "what's the difference",
    "what is the difference", "is there a ",
)
_SIMPLE_GREETINGS = frozenset({
    "hi", "hello", "hey", "thanks", "thank you", "ok", "okay",
    "cool", "nice", "got it", "understood", "great", "perfect", "good",
    "yes", "no", "sure", "alright",
})
_TOOL_HINTS = (
    # filesystem / system actions
    "file", "folder", "directory", "scan", "port", "network",
    "run ", "execute", "install", "process", "service", "log",
    "find ", "search", "list ", "show me", "my ", "this machine",
    "the system", "exploit", "hack", "ctf", "shell", "reverse",
    "payload", "upload", "download", "start ", "open ",
    # hardware / OS queries (need execute_command / get_system_specs)
    "drive", "disk", "storage", "memory", "ram", "cpu", "gpu",
    "size of", "capacity", "free space", "hard drive",
    # real-time data (need search_web)
    "price", "cost", "rate ", " now", "right now", "current",
    "today", "latest", "live ", "weather", "stock", "crypto",
    "bitcoin", "gold", "silver", "market", "exchange rate",
)

def _is_simple_query(text: str) -> bool:
    """True for conversational/factual questions that don't need any tools."""
    t = text.strip().lower().rstrip("?!. ")
    if t in _SIMPLE_GREETINGS:
        return True
    if len(text) > 160:
        return False
    if not any(text.lower().startswith(p) for p in _SIMPLE_PREFIXES):
        return False
    # Exclude if it asks about something tool-related
    return not any(h in text.lower() for h in _TOOL_HINTS)


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


# --- Agent Planner / State Tracker ---
class AgentPlanner:
    """Tracks a multi-step plan derived from the AI's <thinking> block."""

    def __init__(self):
        self.steps: list = []
        self.done: list = []
        self.current: int = 0

    def reset(self):
        self.steps = []
        self.done = []
        self.current = 0

    def set_plan(self, steps: list):
        self.steps = [str(s).strip() for s in steps if str(s).strip()]
        self.done = [False] * len(self.steps)
        self.current = 0

    def advance(self):
        """Mark current step done and move pointer to next pending step."""
        if 0 <= self.current < len(self.done):
            self.done[self.current] = True
        while self.current < len(self.steps) and self.done[self.current]:
            self.current += 1

    @property
    def is_active(self) -> bool:
        return bool(self.steps) and self.current < len(self.steps)

    @property
    def is_complete(self) -> bool:
        return bool(self.steps) and all(self.done)

    def status_panel_text(self) -> str:
        lines = []
        for i, step in enumerate(self.steps):
            if self.done[i]:
                lines.append(f"  [green]✓[/green]  {step}")
            elif i == self.current:
                lines.append(f"  [bold cyan]▶[/bold cyan]  [bold]{step}[/bold]")
            else:
                lines.append(f"  [dim]○  {step}[/dim]")
        return "\n".join(lines)

    def status_line(self) -> str:
        """Compact one-line status, e.g. after a tool call."""
        parts = []
        for i, step in enumerate(self.steps):
            if self.done[i]:
                parts.append(f"[green]✓ {step}[/green]")
            elif i == self.current:
                parts.append(f"[bold cyan]▶ {step}[/bold cyan]")
            else:
                parts.append(f"[dim]○ {step}[/dim]")
        return "  ".join(parts)

    def as_prompt_context(self) -> str:
        if not self.steps:
            return ""
        lines = ["CURRENT PLAN (follow these steps in order):"]
        for i, step in enumerate(self.steps):
            mark = "✓ DONE" if self.done[i] else ("▶ NOW" if i == self.current else "○ PENDING")
            lines.append(f"  Step {i + 1} [{mark}]: {step}")
        lines.append("")
        return "\n".join(lines)


# --- CLI Config ---
_DEFAULT_MODELS_CFG = {
    "_comment": "Navy model configuration. Set your API keys here or via environment variables.",
    "default": "qwen2.5:14b",
    "providers": {
        "_comment": "API keys for cloud providers. Leave empty string to use environment variables instead.",
        "gemini":    {"api_key": "", "_api_key_env": "GEMINI_API_KEY"},
        "openai":    {"api_key": "", "_api_key_env": "OPENAI_API_KEY"},
        "anthropic": {"api_key": "", "_api_key_env": "ANTHROPIC_API_KEY"},
    },
    "presets": {
        "_comment": "Short aliases you can use instead of full model names.",
        "flash":   "gemini-1.5-flash",
        "pro":     "gemini-1.5-pro",
        "2flash":  "gemini-2.0-flash",
        "gpt4o":   "gpt-4o",
        "gpt4m":   "gpt-4o-mini",
        "o3":      "o3",
        "o4":      "o4-mini",
        "sonnet":  "claude-sonnet-4-5",
        "opus":    "claude-opus-4-5",
        "haiku":   "claude-haiku-4-5",
        "kimi":    "kimi-k2.5:cloud",
        "qwen7":   "qwen2.5:7b",
        "qwen14":  "qwen2.5:14b",
        "qwen32":  "qwen2.5:32b",
        "qwen72":  "qwen2.5:72b",
        "code":    "deepseek-coder-v2:16b",
        "ds":      "deepseek-r1:14b",
        "llama":   "llama3.2:latest",
        "mistral": "mistral:latest",
        "phi":     "phi4:latest",
    },
}


def _load_models_config() -> dict:
    """Load models.json. Checks CWD, ~/.config/navy/, then the script/package directory.
    Auto-creates ~/.config/navy/models.json on first run if not found anywhere."""
    _home_cfg = os.path.join(os.path.expanduser("~"), ".config", "navy")
    search_dirs = [os.getcwd(), _home_cfg, os.path.dirname(os.path.abspath(__file__))]
    for d in search_dirs:
        path = os.path.join(d, "models.json")
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            log.warning("Could not load models.json from %s: %s", path, e)
    # Not found anywhere — auto-create at ~/.config/navy/models.json
    dest = os.path.join(_home_cfg, "models.json")
    try:
        os.makedirs(_home_cfg, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(_DEFAULT_MODELS_CFG, f, indent=2)
        console.print(
            f"[green]Created default config:[/] [cyan]{dest}[/]\n"
            "[dim]Edit it to set your default model and API keys.[/]"
        )
    except Exception as e:
        log.warning("Could not auto-create models.json: %s", e)
    return _DEFAULT_MODELS_CFG


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
        "tool_output_truncate": 3000,
        "max_turns": 15,
        "default_ctx": 32768,
        "max_response_tokens": 4096,
        "default_model": default_model,
        "audit_log": os.path.join(_runtime_dir, "navy_audit.log"),
        "sessions_dir": os.path.join(_runtime_dir, "navy_sessions"),
    }
    # Check CWD, ~/.config/navy/, then script directory
    _home_cfg = os.path.join(os.path.expanduser("~"), ".config", "navy")
    for _dir in (_cwd, _home_cfg, _script_dir):
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
        self._transcript = []
        self._current_task: asyncio.Task | None = None
        self.planner = AgentPlanner()
        self._extra_turns: int = 0
        self._dead_native_cmds: set = set()

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

        else:  # ollama
            if not OLLAMA_AVAILABLE:
                raise RuntimeError(
                    f"Model '{self.model}' was detected as an Ollama model (contains ':') "
                    "but the 'ollama' package is not installed.\n"
                    "  pip install ollama\n"
                    "If this is not an Ollama model, specify the provider explicitly via --model "
                    "or set the correct name (e.g. a cloud API model without ':' in the name)."
                )

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
        max_tok = self._cli_cfg["max_response_tokens"]

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
                gen_config = genai.types.GenerationConfig(temperature=0.2, max_output_tokens=max_tok)

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
                        max_tokens=max_tok,
                        stream=True,
                    ):
                        delta = chunk.choices[0].delta.content or ""
                        full_text += delta
                        token_count += 1
                        if token_count % 25 == 0:
                            live.update(Spinner("dots", text=f"Receiving... ({token_count} tokens)", style="cyan"))

            # --- Anthropic ---
            elif self.provider == "anthropic":
                anth_msgs = [m for m in full_messages if m["role"] != "system"]

                def _anthropic_stream():
                    buf = ""
                    with self._anthropic_client.messages.stream(
                        model=self.model,
                        max_tokens=max_tok,
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
                            options={"num_ctx": self.ctx_size, "num_predict": max_tok, "temperature": 0.2},
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
                            options={"num_ctx": self.ctx_size, "num_predict": max_tok, "temperature": 0.2},
                        )
                    full_text = resp["message"]["content"]

        except asyncio.CancelledError:
            raise  # propagate so main_loop can show "Interrupted"
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
        plan_steps = []
        think_match = re.search(r'<thinking>(.*?)</thinking>', text, re.DOTALL | re.IGNORECASE)
        if think_match:
            reasoning = think_match.group(1).strip()
            # Extract <plan> block if present
            plan_match = re.search(r'<plan>(.*?)</plan>', reasoning, re.DOTALL | re.IGNORECASE)
            if plan_match:
                for line in plan_match.group(1).strip().splitlines():
                    line = re.sub(r'^[\d]+[.)]\s*', '', line.strip())   # strip "1." "1)"
                    line = re.sub(r'^[-*•·]\s*', '', line).strip()      # strip "- " "* "
                    if line:
                        plan_steps.append(line)
                reasoning = reasoning.replace(plan_match.group(0), "").strip()
            text = text.replace(think_match.group(0), "")

        clean_text = re.sub(r'```json', '', text, flags=re.IGNORECASE).replace('```', '').strip()
        candidate = self._find_json_in_text(clean_text)
        json_data = self._try_parse_json(candidate) if candidate else None
        return reasoning, plan_steps, json_data, clean_text

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

    def _build_system_prompt(self, env_info: dict, plan_context: str = "") -> str:
        _is_windows = "windows" in env_info.get("os", "").lower()
        # Dead native commands block — injected so AI never retries them bare
        _dead_block = ""
        if self._dead_native_cmds:
            _dead_block = (
                f"UNAVAILABLE NATIVE COMMANDS: {', '.join(sorted(self._dead_native_cmds))} "
                "— NOT installed on this system. Do NOT run them bare. "
                "On Windows use WSL (wsl -d kali-linux -- <tool>) instead.\n\n"
            )
        _pentest_env_note = (
            "   - WSL KALI: Run Kali tools directly — do NOT use bash -c (quoting breaks). "
            "Correct: command=wsl, args=[\"-d\",\"kali-linux\",\"--\",\"gobuster\",\"dir\",\"-u\",\"http://...\",\"-w\",\"wordlist\",\"-t\",\"50\"]. "
            "Wrong: wsl -d kali-linux -- bash -c \"gobuster ...\". "
            "For nmap use IP/hostname only, NOT URLs. Long scans may timeout — set a higher timeout in the JSON.\n"
            if _is_windows else
            "   - LINUX PENTEST: You are already on Linux. Run tools DIRECTLY without any 'wsl' prefix "
            "(e.g. nmap 10.0.0.1, nikto -h http://10.0.0.1, gobuster dir -u ...). "
            "Use IP/hostname only for nmap, NOT URLs.\n"
        )
        return (
            f"SYSTEM STATUS:\n"
            f"- OS: {env_info.get('os')} | Shell: {env_info.get('shell')}\n"
            f"- CWD: {env_info.get('cwd')}\n"
            f"- FILES: {env_info.get('files_in_cwd')}\n"
            + (_dead_block if _dead_block else "")
            + (f"\n{plan_context}" if plan_context else "")
            + "\n### INSTRUCTIONS ###\n"
            "You are Navy, a powerful persistent CLI Agent. Be concise and action-oriented.\n"
            "1. MEMORY: You remember previous messages in the conversation.\n"
            "2. ACT, DON'T SUGGEST: You have tools — USE THEM. Never output a command block and ask the user to run it.\n"
            "   If something can be done with execute_command, write_file, fetch_url, or any tool — DO IT YOURSELF immediately.\n"
            "   The ONLY exceptions are things that require an interactive terminal that must stay open (e.g. a netcat listener\n"
            "   waiting for a connection) — for those, tell the user to run it in a separate window, then continue with your next step.\n"
            "   Examples of what you must NEVER do:\n"
            "   - Output 'Run this command: curl ...' and wait — just run it with execute_command.\n"
            "   - Ask 'Want me to create the WAR file?' — just create it.\n"
            "   - Output a Python script block and say 'run this' — just execute it with execute_command python -c '...'.\n"
            "   - Say 'Let me do X' or 'Running now:' or 'Starting:' in a chat message and stop — just DO X immediately.\n"
            "   - WSL COMMANDS: Pass each arg separately — do NOT use bash -c for single-tool commands.\n"
            "     Good: {\"command\":\"wsl\",\"args\":[\"-d\",\"kali-linux\",\"--\",\"gobuster\",\"dir\",\"-u\",\"http://x\",\"-t\",\"50\"]}\n"
            "     Bad:  {\"command\":\"wsl\",\"args\":[\"-d\",\"kali-linux\",\"--\",\"bash\",\"-c\",\"gobuster dir -u http://x -t 50\"]}\n"
            "   - WSL PIPES: The | pipe operator is a shell feature. For piped WSL commands you MUST wrap in bash -c:\n"
            "     Good: {\"command\":\"wsl\",\"args\":[\"-d\",\"kali-linux\",\"--\",\"bash\",\"-c\",\"curl -s http://x | grep -i password\"]}\n"
            "     Bad:  {\"command\":\"wsl\",\"args\":[\"-d\",\"kali-linux\",\"--\",\"curl\",\"-s\",\"http://x\",\"|\",\"grep\",\"-i\",\"password\"]}\n"
            "     (without bash -c, the | is consumed by Windows cmd and grep runs natively — not found)\n"
            "3. FORMAT: Output <thinking>Your reasoning. For multi-step tasks, include a <plan> block inside thinking:\n"
            "   <plan>\n"
            "     Step 1: short action phrase\n"
            "     Step 2: short action phrase\n"
            "   </plan>\n"
            "   Keep steps ≤ 6, each ≤ 10 words. Then output JSON immediately after </thinking>.\n"
            "   </thinking> must appear before any JSON. No prose between </thinking> and the JSON.\n"
            "   - STOP EARLY: As soon as a tool result answers the user's question, use {\"action\": \"chat\"} immediately. Do NOT run extra commands to verify or reconfirm what you already know.\n"
            "4. BASIC ACTIONS:\n"
            "   - {\"tool\": \"execute_command\", \"command\": \"...\", \"args\": [...]}\n"
            "   - {\"tool\": \"read_file\", \"path\": \"...\"}  (LOCAL files under CWD only)\n"
            "   - {\"tool\": \"fetch_url\", \"url\": \"...\"}  (web pages)\n"
            "   - {\"tool\": \"write_file\", \"path\": \"...\", \"content\": \"...\"}\n"
            "   - {\"tool\": \"search_web\", \"query\": \"...\"}\n"
            "   - {\"tool\": \"search_files\", \"pattern\": \"*.py\", \"directory\": \".\", \"content\": \"optional text to grep\"}\n"
            "   - {\"tool\": \"get_system_specs\"}  — GPU/RAM/CPU (no args)\n"
            "   - {\"tool\": \"get_security_logs\"}  — Windows Security/Defender events (no args)\n"
            "   - {\"action\": \"chat\", \"message\": \"...\"}  — for greetings, answers, summaries\n"
            "5. PENTEST TOOLS (authorized targets only):\n"
            "   - {\"tool\": \"scan_ports\", \"host\": \"...\", \"ports\": \"1-1024,8080\"}  — supports ranges\n"
            "   - {\"tool\": \"http_probe\", \"url\": \"...\"}  — HTTP status + headers (handles self-signed certs)\n"
            "   - {\"tool\": \"dns_lookup\", \"hostname\": \"...\"}\n"
            "   - {\"tool\": \"ssl_check\", \"host\": \"...\", \"port\": 443}  — cert validity, expiry, cipher\n"
            "   - {\"tool\": \"check_security_headers\", \"url\": \"...\"}  — compliance/audit ONLY, NOT for CTF/exploitation\n"
            "   - {\"tool\": \"whois_lookup\", \"domain\": \"...\"}  — registrar, expiry, nameservers\n"
            "   - {\"tool\": \"subdomain_scan\", \"domain\": \"...\", \"extra_words\": \"word1,word2\"}  — DNS enumeration\n"
            "6. EXPERT KNOWLEDGE:\n"
            "   - COMPILATION: C/C++ on Windows with MinGW/Sockets: gcc file.c -o file.exe -lws2_32 -liphlpapi\n"
            "   - WINDOWS: Prefer PowerShell for OS info (Get-PSDrive, Get-CimInstance); wmic is deprecated.\n"
            "   - RECON WORKFLOW (web audit): scan_ports → http_probe → ssl_check → subdomain_scan → whois_lookup.\n"
            "     check_security_headers is for compliance audits ONLY — skip it during CTF/exploitation/active attacks.\n"
            "   - Do NOT use read_file for URLs; use fetch_url. Do NOT use wsl for native Linux tools.\n"
            + _pentest_env_note +
            "   - COMMAND NOT FOUND: If a command returns 'not recognized', 'command not found', or 'No such file or directory',\n"
            "     it is NOT installed on this OS. Never retry it bare. Immediately switch to the WSL equivalent:\n"
            "     wsl -d kali-linux -- <tool> (on Windows). Do not try Python wrappers or net use as fallbacks first.\n"
            "   - WSL FILE PATHS: Files downloaded inside WSL (smbclient get, wget, curl -o) live in the WSL filesystem.\n"
            "     Read them with: wsl -d kali-linux -- cat /path/to/file\n"
            "     NEVER look for them at C:\\, E:\\, or any Windows path — those paths don't contain WSL files.\n"
            "   - SMBCLIENT SYNTAX: 'ls dir' only shows the dir entry, not its contents. To list a subdirectory use:\n"
            "     smbclient ... -c 'cd dirname; ls'   OR   smbclient ... -c 'ls dirname\\\\'\n"
            "     To read a file directly: smbclient ... -c 'more dir/file.txt' (prints to stdout — no download needed).\n"
            "     To download: smbclient ... -c 'get dir/file.txt' then read with: wsl -d kali-linux -- cat /tmp/file.txt\n"
            "   - ATTACKER IP: When creating reverse shells or payloads, ALWAYS ask the user for their attacker/listener IP "
            "first if it is not already known. Do NOT hardcode a placeholder; the shell must connect back to the right IP.\n"
            "   - PAYLOAD USAGE: After writing any exploit file (shell.jsp, shell.py, shell.war, etc.), do NOT ask the user "
            "if they want you to package/deploy it — just do it. Package the WAR, run the deploy curl, trigger the shell. "
            "Only pause to tell the user to start a listener in a separate window (since that requires an open terminal).\n"
            "   - WAR FILES: A valid Tomcat WAR requires WEB-INF/web.xml inside it. When creating a WAR, always write "
            "WEB-INF/web.xml first then package both files: "
            "zip -r shell.war shell.jsp WEB-INF/ (on Linux) or use Python zipfile to add both paths.\n"
            "   - OS CONSISTENCY: The host OS is shown in SYSTEM STATUS. When running on Windows and attacking a Linux "
            "target, netcat listeners and shell commands for the *attacker side* must match the host OS. "
            "On Windows use: ncat or ncat.exe for listeners; avoid /dev/null, use nul instead.\n"
            "   - TRUNCATED OUTPUT: If a tool result ends with '... (truncated)', the file is too large to read whole. "
            "Do NOT re-fetch it — pipe it through grep instead to extract only what you need. "
            "Example: curl -s <url> | grep -i 'password\\|insert\\|admin\\|user' "
            "For SQL dumps specifically: curl -s <url> | grep -i 'INSERT' to find credential rows. "
            "Never call the same URL twice with the same command — always change the approach.\n"
            "   - GAMING: When asked 'good for gaming?', call get_system_specs() first, then assess GPU/RAM/CPU.\n"
            "   - SECURITY LOGS: For 'suspicious activity', 'defender logs', call get_security_logs() first.\n"
            "   - FILE SEARCH: Use search_files to find files by name or content before read_file.\n"
        )


    async def _process_input(self, session, user_in: str, env_info: dict = None) -> dict:
        """Run the AI agent loop for a single user input. Returns updated env_info."""
        try:
            return await self._process_input_inner(session, user_in, env_info)
        except asyncio.CancelledError:
            raise
        except KeyboardInterrupt:
            raise asyncio.CancelledError()

    async def _process_input_inner(self, session, user_in: str, env_info: dict = None) -> dict:
        # --- Update env info ---
        try:
            res = await session.call_tool("get_environment_metadata", {})
            env_info = json.loads(res.content[0].text)
        except Exception as e:
            log.debug("Env metadata update failed: %s", e)
            if env_info is None:
                env_info = {}

        self.memory.add("user", user_in)
        self.audit.log_user(user_in)

        # --- Simple query fast path ---
        if _is_simple_query(user_in):
            simple_prompt = (
                "You are Navy, a knowledgeable AI assistant. "
                "Answer the question directly and concisely in plain text. "
                "No JSON, no tool calls, no markdown headers — just a clear conversational answer."
            )
            answer = await self.call_ai(simple_prompt, self.memory.get_history())
            if not answer.startswith("API ERROR:"):
                self.memory.add("assistant", answer)
                self.audit.log_assistant(answer)
                console.print(Panel(Markdown(answer), title="[bold cyan]⚓ Navy[/]", border_style="cyan", padding=(0, 1)))
                return env_info

        # --- Reset planner for this query ---
        self.planner.reset()

        max_turns = self._cli_cfg["max_turns"] + self._extra_turns
        self._extra_turns = 0  # consume extra turns for this call
        turn = 0
        retry_count = 0
        recent_tool_calls = []   # rolling window: (cmd_hash, result_hash) pairs — loop only if same result too
        loop_stop_turns = 0      # how many remaining turns after a loop stop (0 = no limit)
        _plan_shown = False      # show plan panel only on first extraction

        while turn < max_turns:
            if loop_stop_turns and turn >= loop_stop_turns:
                console.print("[bold red]⚠  Agent could not break the loop — stopping.[/]")
                break
            turn += 1
            # Rebuild system prompt each turn so plan context stays current
            sys_prompt = self._build_system_prompt(env_info, self.planner.as_prompt_context())
            try:
                ai_msg = await self.call_ai(sys_prompt, self.memory.get_history())
            except (KeyboardInterrupt, asyncio.CancelledError):
                raise asyncio.CancelledError()
            if ai_msg.startswith("API ERROR:"):
                # Context too long — prune history and retry once
                if "context length" in ai_msg.lower() or "prompt too long" in ai_msg.lower() or "max context" in ai_msg.lower():
                    console.print("[yellow]⚠  Context too long — trimming history and retrying...[/]")
                    h = self.memory.get_history()
                    # Drop oldest 25% of messages (min 2) to make room
                    drop = max(2, len(h) // 4)
                    self.memory.replace_history(h[drop:])
                    turn -= 1  # don't count this as a turn
                    continue
                console.print(f"[bold red]{ai_msg}[/]")
                break

            reason, plan_steps, data, raw_text = self.extract_response(ai_msg)

            # Initialize planner from first <plan> block we see
            if plan_steps and not _plan_shown:
                self.planner.set_plan(plan_steps)
                _plan_shown = True
                console.print(Panel(
                    self.planner.status_panel_text(),
                    title="[bold blue]📋 Plan[/bold blue]",
                    border_style="blue",
                    expand=False,
                    padding=(0, 2),
                ))

            if reason:
                console.print(Panel(
                    Text(reason, style="dim"),
                    title="[dim]💭 thinking[/dim]",
                    border_style="dim",
                    expand=False,
                    padding=(0, 1),
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
                        console.print("[bold red]⚠  Agent stuck — try rephrasing your request.[/]")
                        break
                # Suppress empty panels — blank AI response treated as a nudge
                if not ai_msg.strip():
                    if retry_count < 2:
                        self.memory.add("user", "System: Your last response was empty. Output a JSON action or {\"action\":\"chat\"} now.")
                        retry_count += 1
                        continue
                    break
                console.print(Panel(Markdown(ai_msg), title="[bold cyan]⚓ Navy[/]", border_style="cyan", padding=(0, 1)))
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
                    # Deduplicate: models sometimes repeat the same sentence twice
                    half = len(msg) // 2
                    if half > 20 and msg[:half].strip() == msg[half:].strip():
                        msg = msg[:half].strip()
                    if not msg and reason:
                        msg = reason[:800] + ("..." if len(reason) > 800 else "")
                    if not msg:
                        msg = "See the output above, or ask again with more detail."
                    # Detect "placeholder" messages — AI announcing intent but not acting.
                    # e.g. "Let me run the scan:", "Running now:", "I'll do it:"
                    _placeholder_phrases = (
                        "let me", "i'll ", "i will ", "running now", "starting now",
                        "i'm going to", "i am going to", "let's ", "let us ",
                    )
                    _is_placeholder = (
                        len(msg) < 250
                        and (
                            msg.rstrip().endswith(":")
                            or any(msg.lower().startswith(p) for p in _placeholder_phrases)
                            or any(p in msg.lower()[:80] for p in _placeholder_phrases)
                        )
                    )
                    if _is_placeholder and retry_count < 2:
                        self.memory.add("assistant", msg)
                        self.memory.add("user", "System: Stop announcing — execute the action now with the appropriate tool JSON.")
                        retry_count += 1
                        continue
                    # Skip truly empty chat responses
                    if not msg.strip():
                        task_completed = True
                        break
                    console.print(Panel(Markdown(msg), title="[bold cyan]⚓ Navy[/]", border_style="cyan", padding=(0, 1)))
                    self.memory.add("assistant", msg)
                    self.audit.log_assistant(msg)
                    task_completed = True
                    break

                tool = step.get("tool")
                if not tool:
                    continue

                # Loop detection — rolling window: trigger only when SAME command AND SAME result
                if tool == "execute_command":
                    _cmd_hash = f"execute_command::{step.get('command')}::{step.get('args')}"
                else:
                    _cmd_hash = f"{tool}::{json.dumps({k: v for k, v in step.items() if k not in ['tool','action']}, sort_keys=True)}"
                # result_hash will be filled in after the tool call; store placeholder for now
                _pending_cmd_hash = _cmd_hash

                # Confirmations
                if not self.skip_confirm:
                    if tool == "execute_command":
                        cmd_display = step.get("command", "") + " " + " ".join(str(a) for a in step.get("args", []))
                        if not _confirm_arrow(f"💻 Run  {cmd_display.strip()[:80]}"):
                            tool_outputs.append("System: User declined execute_command.")
                            continue
                    elif tool == "write_file":
                        if not _confirm_arrow(f"📝 Write  {step.get('path', '?')}"):
                            tool_outputs.append("System: User declined write_file.")
                            continue
                    elif tool in ("scan_ports", "subdomain_scan"):
                        icon = _TOOL_ICONS.get(tool, "🔧")
                        target = step.get("host") or step.get("domain") or "?"
                        if not _confirm_arrow(f"{icon} {tool}  {target}  (authorized targets only)"):
                            tool_outputs.append(f"System: User declined {tool}.")
                            continue
                    elif tool in ("http_probe", "ssl_check", "check_security_headers", "whois_lookup"):
                        icon = _TOOL_ICONS.get(tool, "🔧")
                        target = step.get("url") or step.get("host") or step.get("domain") or "?"
                        if not _confirm_arrow(f"{icon} {tool}  {target}  (authorized only)"):
                            tool_outputs.append(f"System: User declined {tool}.")
                            continue

                icon = _TOOL_ICONS.get(tool, "🔧")
                console.print(f"[bold yellow]{icon} {tool}[/]")

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
                    icon = _TOOL_ICONS.get(tool, "🔧")
                    disp = result_text[:700] + "..." if len(result_text) > 700 else result_text
                    console.print(Panel(
                        disp,
                        title=f"[bold {color}]{icon} {tool}[/]",
                        border_style=color,
                        padding=(0, 1),
                    ))
                    self.audit.log_tool(tool, result_text)

                    # --- Result-aware loop detection ---
                    _result_hash = result_text[:120]
                    _call_sig = (_pending_cmd_hash, _result_hash)
                    recent_tool_calls.append(_call_sig)
                    if len(recent_tool_calls) > 8:
                        recent_tool_calls.pop(0)
                    if recent_tool_calls.count(_call_sig) >= 2:
                        console.print("[bold red]⚠  Loop detected: same command, same result. Stopping.[/]")
                        last_outputs = "\n".join(tool_outputs[-3:]) if tool_outputs else "No new results."
                        _loop_hint = ""
                        if tool in ("fetch_url", "execute_command"):
                            _loop_hint = (
                                " The output was likely truncated. "
                                "Pipe through grep to extract only what you need, or use a different subcommand."
                            )
                        self.memory.add("user", (
                            f"System: LOOP STOPPED. '{tool}' returned the same result every time.{_loop_hint} "
                            f"Do NOT call '{tool}' with the same arguments again. "
                            f"Last result snippet:\n{last_outputs[:500]}\n"
                            "Change your approach: different tool, different args, or pipe through grep. "
                            "Then use {\"action\": \"chat\"} to report findings."
                        ))
                        recent_tool_calls.clear()
                        loop_stop_turns = turn + 2
                        retry_count = 0
                        break

                    # --- Track dead native commands (not installed on this OS) ---
                    _dead_patterns = (
                        "is not recognized as an internal or external command",
                        "command not found",
                        "no such file or directory",
                    )
                    if tool == "execute_command" and any(p in result_text.lower() for p in _dead_patterns):
                        _dead_cmd = step.get("command", "")
                        if _dead_cmd and "wsl" not in _dead_cmd.lower():
                            self._dead_native_cmds.add(_dead_cmd)

                    # Advance planner on successful tool calls
                    if not is_error and self.planner.is_active:
                        self.planner.advance()
                        if len(self.planner.steps) > 1:
                            console.print(f"  {self.planner.status_line()}")

                    truncate = self._cli_cfg["tool_output_truncate"]
                    summary = result_text if len(result_text) <= truncate else result_text[:truncate] + "\n... (truncated)"
                    tool_outputs.append(f"Tool: {tool}\nResult: {summary}")

                    # --- STOP EARLY nudge: short non-error result likely answers the question ---
                    if not is_error and len(result_text) < 300 and turn >= 1:
                        tool_outputs.append(
                            "System: The above result is short and may fully answer the question. "
                            "If it does, use {\"action\": \"chat\"} immediately with the answer — do NOT run another command."
                        )

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
            console.print(f"[bold yellow]⚠  Max turns ({max_turns}) reached — type [bold]continue[/bold] to give me more turns.[/]")
        return env_info

    async def main_loop(self):
        ver = "4.1.1"
        console.print()
        console.print(Panel(
            f"[bold cyan]⚓  NAVY[/bold cyan]  [dim]v{ver}[/dim]\n"
            f"\n"
            f"  [dim]Model   [/dim][bold white]{self.model}[/bold white]  [dim]·  {self.provider}[/dim]\n"
            f"  [dim]Context [/dim][white]{self.ctx_size:,} tokens[/white]  [dim]·  Audit  on[/dim]\n"
            f"\n"
            f"  [dim]/help · /models · model <alias> · /save · /reset[/dim]\n"
            f"  [dim]Ctrl+C  interrupt  ·  exit / quit  to leave[/dim]",
            border_style="cyan",
            expand=False,
            padding=(0, 2),
        ))
        console.print()

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
                    # --- Prompt ---
                    try:
                        cwd_display = env_info.get("cwd", ".")
                        home = os.path.expanduser("~")
                        if cwd_display.startswith(home):
                            cwd_display = "~" + cwd_display[len(home):]
                        user_in = console.input(
                            f"\n[bold cyan]⚓[/bold cyan] [blue]{cwd_display}[/blue] [bold white]❯[/bold white] "
                        ).strip()
                    except KeyboardInterrupt:
                        console.print("")
                        continue
                    except EOFError:
                        break

                    if not user_in:
                        continue

                    # Wrap everything so Ctrl+C never kills the session
                    try:
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
                            table.add_row("continue / /continue", "Give the agent +10 more turns to finish a task")
                            table.add_row("/reset", "Clear conversation memory")
                            table.add_row("/save [name]", "Save current session for later reload")
                            table.add_row("/sessions", "List saved sessions")
                            table.add_row("/load <name>", "Load a saved session")
                            table.add_row("/export [file]", "Export conversation as Markdown transcript")
                            table.add_row("clear / cls", "Clear terminal screen")
                            table.add_row("exit / quit", "Exit Navy")
                            console.print(table)
                            continue

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

                        if cmd.lower().startswith("/save"):
                            parts = cmd.split(None, 1)
                            name = parts[1].strip() if len(parts) > 1 else None
                            try:
                                path = self.sessions.save(self.memory.get_history(), self.model, name)
                                console.print(f"[green]Session saved to {path}[/]")
                            except Exception as e:
                                console.print(f"[red]Save failed: {e}[/]")
                            continue

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

                        if cmd.lower().startswith("/export"):
                            parts = cmd.split(None, 1)
                            fname = parts[1].strip() if len(parts) > 1 else f"navy_transcript_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                            try:
                                self.sessions.export_markdown(self.memory.get_history(), self.model, fname)
                                console.print(f"[green]Transcript exported to {fname}[/]")
                            except Exception as e:
                                console.print(f"[red]Export failed: {e}[/]")
                            continue

                        if cmd.lower().startswith("model ") or cmd.lower().startswith("/model "):
                            new_name = cmd.split(None, 1)[1].strip() if " " in cmd else ""
                            if not new_name:
                                console.print("[yellow]Usage: model <name>  e.g.  model gpt-4o[/]")
                            elif self.switch_model(new_name):
                                console.print(f"[green]Model set to [bold]{self.model}[/] (provider: {self.provider})[/]")
                            continue

                        if cmd.lower() in ("continue", "/continue"):
                            self._extra_turns += 10
                            user_in = (
                                "Continue with the previous task. "
                                "Do NOT re-scan or re-explain what was already found — "
                                "pick up exactly at the next pending step."
                            )
                            console.print(f"[dim cyan]↺  +10 turns — resuming task...[/dim cyan]")
                            # Fall through to AI agent below

                        # --- AI agent ---
                        self._current_task = asyncio.create_task(
                            self._process_input(session, user_in, env_info)
                        )
                        try:
                            env_info = await self._current_task
                        except (KeyboardInterrupt, asyncio.CancelledError):
                            # Cancel and AWAIT the task to fully drain the pending exception
                            # before the next loop iteration — without this the CancelledError
                            # or KeyboardInterrupt leaks into the next command's first await.
                            if not self._current_task.done():
                                self._current_task.cancel()
                            try:
                                await self._current_task
                            except BaseException:
                                # BaseException covers CancelledError AND KeyboardInterrupt
                                pass
                            console.print("\n[bold yellow]⏹  Interrupted[/bold yellow]")
                        finally:
                            self._current_task = None

                    except (KeyboardInterrupt, asyncio.CancelledError):
                        # Ctrl+C during command dispatch (not during AI task)
                        t, self._current_task = self._current_task, None
                        if t and not t.done():
                            t.cancel()
                            try:
                                await t
                            except BaseException:
                                pass
                        console.print("\n[bold yellow]⏹  Interrupted — ready[/bold yellow]")


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
        _cfg_path = os.path.join(os.path.expanduser("~"), ".config", "navy", "models.json")
        console.print(
            "[red]No model configured.[/]\n"
            f"[yellow]Option 1 (recommended):[/] create [cyan]{_cfg_path}[/]\n"
            "          Download the template from: https://github.com/Zrnge/navy-ai/blob/master/models.json\n"
            "[yellow]Option 2:[/] pass [cyan]--model <name>[/]  e.g.  [dim]navy --model qwen2.5:14b 'hi'[/]\n"
            "[yellow]Option 3:[/] place [cyan]models.json[/] in your current working directory."
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
        sys.exit(1)


if __name__ == "__main__":
    cli_entry()
