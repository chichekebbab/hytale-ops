# Hytale Ops CLI 🎮

> **Ultra-lightweight CLI to deploy and manage Hytale servers on Hetzner Cloud.**
> Zero dependencies. Single bash script. Interactive.

[![Hetzner Cloud](https://img.shields.io/badge/Hetzner-Cloud-red)](https://hetzner.cloud)
[![Bash](https://img.shields.io/badge/Written%20in-Bash-4EAA25)](https://www.gnu.org/software/bash/)

## Why Hytale Ops?

Unlike complex infrastructure-as-code tools, **Hytale Ops** is designed for speed and simplicity. It's a single script you can run from anywhere (macOS, Linux, WSL) to spin up a game server in ~2 minutes.

- **🚀 Instant Deploy:** Provisions optimized VPS (`cx22` to `cpx41`) on Hetzner.
- **☕️ Java 25 Ready:** Automatically installs OpenJDK 25 (required for Hytale).
- **🔒 Secure:** Handles SSH keys and Firewall (UFW) rules automatically.
- **🤖 Interactive:** Guided menus for server size, location, and configuration.
- **💸 Cost-Effective:** Estimates monthly costs before you deploy.

## Requirements

- **Bash** (macOS, Linux, or WSL on Windows)
- **curl** & **ssh** (standard on most systems)
- **jq** (lightweight JSON processor - `apt install jq` or `brew install jq`)
- **Hetzner Cloud Token** (Read/Write) - [Get one here](https://console.hetzner.cloud/)

## Quick Start ⚡️

Run this one-liner to download and start the interactive tool:

```bash
git clone https://github.com/chichekebbab/hytale-ops.git
cd hytale-ops
chmod +x hytale-ops.sh
./hytale-ops.sh
```

## Usage

### 1. Interactive Mode (Recommended)
Just run the script without arguments. It will guide you through authentication, server selection, and deployment.
```bash
./hytale-ops.sh
```

### 2. Command Line Arguments
For power users or automation:

| Command | Description | Example |
| :--- | :--- | :--- |
| `deploy` | Create and setup a new server | `./hytale-ops.sh deploy my-server` |
| `status` | Check IP, status, and type | `./hytale-ops.sh status my-server` |
| `ssh` | Connect to the server console | `./hytale-ops.sh ssh my-server` |

## Configuration

The tool automatically saves your Hetzner API token securely in `~/.config/hytale-ops/config.env`.
To reset or change the token, simply edit or delete that file.

## Under the Hood

When you run `deploy`, Hytale Ops:
1.  **Calls Hetzner API** to create a VPS with Cloud-init.
2.  **Injects** your local SSH key (`~/.ssh/id_rsa.pub`) or creates a new one.
3.  **Configures Firewall** to allow SSH (22) and Hytale (25565).
4.  **Installs Dependencies** (Java 25, Hytale user).
5.  **Sets up Systemd** (`hytale.service`) for auto-restart and easy management.

## License

MIT License. Free to use and modify.
Running a Hytale server is subject to Hytale's EULA (once released).
