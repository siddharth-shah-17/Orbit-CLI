# Orbit CLI by SVECTOR

A powerful terminal-based AI assistant that helps with software development tasks.

## Features

- Interactive chat interface with AI capabilities
- Code analysis and understanding
- LSP (Language Server Protocol) integration
- Debug logging and diagnostics
- Multi-platform support (macOS, Linux, Windows)

## Installation

### NPM

```bash
npm install -g orbit-cli-svector
```

### JSR

```bash
npx jsr add @svector/orbit-cli
```

Or with Deno:

```bash
deno install jsr:@svector/orbit-cli
```

## Usage

```bash
# Run in interactive mode
orbit-cli

# Run with debug logging
orbit-cli -d

# Run with debug logging in a specific directory
orbit-cli -d -c /path/to/project

# Print version
orbit-cli -v

# Run a single non-interactive prompt
orbit-cli -p "Explain the use of context in Go"

# Run with JSON output format
orbit-cli -p "Explain the use of context in Go" -f json
```

## Flags

- `-c, --cwd string` - Current working directory
- `-d, --debug` - Enable debug logging
- `-h, --help` - Show help
- `-f, --output-format string` - Output format for non-interactive mode (text, json)
- `-p, --prompt string` - Prompt to run in non-interactive mode
- `-q, --quiet` - Hide spinner in non-interactive mode
- `-v, --version` - Show version

## License

MIT

## Repository

[GitHub](https://github.com/svector-corporation/orbit-cli)
