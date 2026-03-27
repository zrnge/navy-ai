# ⚓ Navy AI

<p align="center">
  <img src="https://img.shields.io/pypi/v/navy-ai?style=for-the-badge&color=cyan&label=PyPI" alt="PyPI Version"/>
  <img src="https://img.shields.io/pypi/pyversions/navy-ai?style=for-the-badge&color=blue" alt="Python Versions"/>
  <img src="https://img.shields.io/github/license/Zrnge/navy-ai?style=for-the-badge&color=green" alt="License"/>
  <img src="https://img.shields.io/pypi/dm/navy-ai?style=for-the-badge&color=orange&label=Downloads" alt="Downloads"/>
  <img src="https://img.shields.io/github/stars/Zrnge/navy-ai?style=for-the-badge&color=yellow" alt="Stars"/>
</p>

<p align="center">
  <b>An AI-powered persistent CLI agent with built-in pentest, recon, and system tools.</b><br/>
  Supports Ollama · OpenAI · Gemini · Anthropic — switch models on the fly.
</p>

---

## Features

- **Interactive & argument mode** — chat in a session or fire a one-liner from your terminal
- **Multi-provider** — Ollama (local), OpenAI, Gemini, Anthropic, or any OpenAI-compatible endpoint
- **Built-in pentest tools** — port scanner, SSL checker, HTTP prober, subdomain enum, WHOIS, and more
- **MCP-based tool server** — extensible, runs as a local subprocess
- **Session management** — save, load, and export conversations as Markdown
- **Audit log** — every command and response is logged locally
- **Dynamic timeouts** — long-running commands like `nmap -p-` get their own timeout budget

---

## Install

```bash
pip install navy-ai
```

Install with your preferred AI provider:

```bash
pip install "navy-ai[ollama]"      # local models via Ollama
pip install "navy-ai[openai]"      # GPT-4o, o3, o4-mini, etc.
pip install "navy-ai[gemini]"      # Gemini 1.5 / 2.0
pip install "navy-ai[anthropic]"   # Claude Sonnet / Opus / Haiku
pip install "navy-ai[all]"         # every provider at once
```

---

## Usage

### Interactive mode

```bash
navy
```

```
navy in /home/user > what ports are open on 10.0.0.1?
navy in /home/user > summarise the files in this folder
navy in /home/user > am i running the latest kernel?
```

### Argument mode (single-shot)

```bash
navy "what is the name of this computer"
navy "how long has this machine been running"
navy --model gpt-4o "scan ports on 10.0.0.1"
navy --yes "what processes are using the most CPU"
```

### Options

| Flag | Description |
|------|-------------|
| `--model <name\|alias>` | Override the model (name or alias from `models.json`) |
| `--ctx <int>` | Context window size (default: 32768) |
| `--yes` / `-y` | Skip all confirmation prompts |

### In-session commands

| Command | Description |
|---------|-------------|
| `model <alias>` | Switch model mid-session |
| `/models` | List all model aliases |
| `/save [name]` | Save the current session |
| `/load <name>` | Load a saved session |
| `/sessions` | List saved sessions |
| `/export [file]` | Export transcript as Markdown |
| `/reset` | Clear conversation memory |
| `exit` / `quit` | Exit Navy |

---

## Configuration

On first run, create `config.json` and `models.json` in your working directory (or copy from the repo).

### `models.json` — set your default model and API keys

```json
{
  "default": "kimi-k2.5:cloud",
  "providers": {
    "openai":    { "api_key": "" },
    "gemini":    { "api_key": "" },
    "anthropic": { "api_key": "" }
  },
  "presets": {
    "kimi":    "kimi-k2.5:cloud",
    "gpt4o":   "gpt-4o",
    "flash":   "gemini-2.0-flash",
    "sonnet":  "claude-sonnet-4-5",
    "qwen14":  "qwen2.5:14b"
  }
}
```

API keys can also be set via environment variables:

```bash
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=AIza...
export ANTHROPIC_API_KEY=sk-ant-...
```

### `config.json` — timeouts and tool limits

```json
{
  "server": {
    "command_timeout": 120,
    "max_command_timeout": 1800
  }
}
```

> **Tip:** For long-running commands like `nmap -p-`, the AI automatically requests a longer timeout. The cap is `max_command_timeout` (default 30 min).

---

## Built-in Tools

| Tool | Description |
|------|-------------|
| `execute_command` | Run shell commands with per-command timeout control |
| `read_file` / `write_file` | Local file read/write |
| `search_files` | Find files by name or content |
| `fetch_url` | Fetch and parse web pages |
| `search_web` | DuckDuckGo search |
| `scan_ports` | TCP port scanner (supports ranges: `1-65535`) |
| `http_probe` | HTTP status + response headers |
| `check_security_headers` | Security header grading (A–F) |
| `ssl_check` | TLS certificate validity, expiry, ciphers |
| `dns_lookup` | DNS resolution |
| `whois_lookup` | Domain registrar, expiry, nameservers |
| `subdomain_scan` | DNS-based subdomain enumeration |
| `get_system_specs` | GPU / RAM / CPU information |
| `get_security_logs` | Windows Security & Defender events |

---

## Pentest Workflow

Navy follows a structured recon workflow when given a target:

```
scan_ports → http_probe → check_security_headers → ssl_check → subdomain_scan → whois_lookup
```

> **Important:** Only use pentest tools against targets you are authorized to test.

---

## License

MIT © [Zrnge](https://github.com/Zrnge)
