# Navy AI

An AI-powered persistent CLI agent with built-in pentest and system tools, supporting Ollama, OpenAI, Gemini, and Anthropic models.

## Install

```bash
pip install navy-ai
```

Install with your preferred AI provider:

```bash
pip install "navy-ai[ollama]"      # local models via Ollama
pip install "navy-ai[openai]"      # GPT-4o, o3, etc.
pip install "navy-ai[gemini]"      # Gemini 1.5 / 2.0
pip install "navy-ai[anthropic]"   # Claude
pip install "navy-ai[all]"         # all providers
```

## Usage

```bash
# Interactive mode
navy

# Single-shot argument mode
navy "what is the name of this computer"
navy "scan ports on 10.0.0.1"
navy --model gpt-4o "summarise the files in this folder"

# Options
navy --model <name|alias>   # override model
navy --ctx 16384            # set context window size
navy --yes                  # skip confirmation prompts (-y)
```

## Configuration

On first run, copy and edit the config files:

| File | Purpose |
|------|---------|
| `config.json` | Timeouts, limits, tool behaviour |
| `models.json` | Default model, provider API keys, aliases |

API keys can be set in `models.json` or via environment variables:

```bash
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=AIza...
export ANTHROPIC_API_KEY=sk-ant-...
```

## Built-in Tools

| Tool | Description |
|------|-------------|
| `execute_command` | Run shell commands (with per-command timeout) |
| `read_file` / `write_file` | Local file access |
| `search_web` | DuckDuckGo search |
| `fetch_url` | Fetch web pages |
| `scan_ports` | TCP port scanner |
| `http_probe` | HTTP status + security headers |
| `ssl_check` | TLS cert validity and ciphers |
| `check_security_headers` | Security header grading |
| `dns_lookup` / `whois_lookup` | DNS and WHOIS |
| `subdomain_scan` | DNS enumeration |
| `get_system_specs` | GPU / RAM / CPU info |
| `get_security_logs` | Windows Security/Defender events |

## License

MIT
