<p align="center">
  <img src="assets/logo.png" alt="Network Virus Identifier logo" width="200">
</p>

 <h1 align="center">NETWORK IDENTIFY VIRUS</h1>
The main purpose of this application is to discover active remote viruses on your network using PowerShell. Remember that this is just an identifier, the removal process will have to be done by you.

> [Português](README.pt-BR.md)

# 🐬 How to install?
1. Install node-js
2. Open the terminal in the project folder and run `npm i` to install all dependencies.
3. In the same terminal, run `node .` to start the application and identify any suspicious processes.

# 📷 Terminal
<img width="1674" height="989" alt="Captura de tela 2026-03-13 112215" src="https://github.com/user-attachments/assets/2c4cb8d1-4846-4bd9-bd26-267bac2842a1" />


---
# 💾 Portable

<details open>
<summary><b>How to install?</b></summary>

1. Go to the [**Releases**](https://github.com/devbluen/Network-Virus-Identifier/releases) tab of this repository.
2. Download the **`NetworkVirusIdentifier.exe`** file.
3. Save it to any folder (or to a USB drive, since it's portable).
4. Double-click to open it and accept the administrator prompt (UAC).

That's it, the monitor starts displaying connections right away.

> To close it, just close the window or press `Ctrl + C`.

</details>

<details>
<summary><b>Requirements</b></summary>

- Windows 10 or later (64-bit)
- **Administrator** permission

> The program uses `netstat` and PowerShell, which already come with Windows. A Linux version is planned for a future update.

</details>

## <b>Antivirus warning</b>

> Since this is an executable that calls PowerShell and `netstat`, Windows Defender and other antivirus software may flag it as a false positive. The source code is open and available in this repository, so you can review it or build your own executable (see the section below).

<details>
<summary><b>How to build the executable (for developers)</b></summary>

The project uses **Node SEA** (Single Executable Applications) to package the code.

### Prerequisites

- [Node.js 20 or later](https://nodejs.org)

### Step by step

```bash
# 1. Clone the repository
git clone https://github.com/devbluen/Network-Virus-Identifier
cd Network-Virus-Identifier

# 2. Install the dependencies
npm i

# 3. Build the executable
node build-sea.js
```

The result is saved at `build/NetworkVirusIdentifier.exe`.

### Project structure

```
Network-Virus-Identifier/
├── assets/
│   └── logo.ico        # executable icon
├── build/              # final executable (generated)
├── dist/               # intermediate files (generated)
├── index.js            # monitor code
├── build-sea.js            # script that builds the executable
├── sea-config.json     # Node SEA configuration
└── package.json
```

</details>

---
# Credits:
- **devbluen** (Created the script)
- [**Shazanxz**](https://github.com/Shazanxz/) (Portable Executable build)