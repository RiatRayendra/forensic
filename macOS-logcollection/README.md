# macOS Forensic Collection Script

A comprehensive macOS forensic collection script designed to gather volatile and non-volatile artifacts from all local (non-system) users on a Mac device M Series. This script is tailored for Incident Response, Threat Hunting, or post-compromise forensic analysis.

## 🚨 Key Features

- Collects system configuration and hardware details.
- Gathers login history, user shell histories, recent file activity.
- Extracts browser history (Chrome, Edge, Safari, Firefox) for each user.
- Captures persistence mechanisms (LaunchAgents, Daemons, crontab, login items).
- Dumps running processes, open network connections, and kernel extensions.
- Gathers environment variables of all users (including root).
- Archives all results into a timestamped ZIP file for offline analysis.


## 📂 Collected Artifact Directory Tree
```text
macOS_Forensic_Collection_[Date]_[time]
├── system_info.txt
├── hardware_info.txt
├── software_info.txt
├── user_list.txt
├── user_activity.txt
├── running_processes.txt
├── top_output.txt
├── network_connections.txt
├── open_ports_lsof.txt
├── network_interfaces.txt
├── arp_cache.txt
├── login_items.txt
├── user_crontab.txt
├── kernel_extensions.txt
├── sip_status.txt
├── environment_vars/
│   ├── user1_env.txt
│   ├── user2_env.txt
│   └── root_env.txt
├── persistence/
│   ├── launchctl_list.txt
│   ├── system_launch_agents.txt
│   └── system_launch_daemons.txt
├── browser_history/
│   ├── user1_chrome_history.txt
│   ├── user1_edge_history.txt
│   ├── user1_safari_history.txt
│   └── user1_firefox_history.txt
├── user_histories/
│   ├── user1_bash_history.txt
│   └── user1_zsh_history.txt
├── files_recent/
│   ├── _system/
│   │   ├── tmp_last90_symlink.txt
│   │   ├── tmp_last90_real.txt
│   │   ├── tmp_filestree_symlink.txt
│   │   ├── tmp_filestree_real.txt
│   │   ├── var_log_last90.txt
│   │   └── var_log_quarantined.txt
│   └── user1/
│       ├── Downloads_last90.txt
│       ├── Documents_last90.txt
│       └── filestree_files.txt
├── recent_apps/
│   ├── system_applications_last90.txt
│   └── user_applications_last90.txt
```

---

## 🛠️ How to Use

```bash
chmod +x logcollection-mac.sh
./logcollection-mac.sh
```

## 📁 Artifact Details

### 🔍 System Info
**Files:**  
`system_info.txt`, `hardware_info.txt`, `software_info.txt`  
**Purpose:**  
Captures system and hardware profile for baseline analysis.

---

### 👤 User Enumeration
**Files:**  
- `user_list.txt` — Lists all users on the system  
- `user_activity.txt` — Login history for each user via the `last` command

---

### 🧠 Process and Memory Snapshots
**Files:**  
`running_processes.txt`, `top_output.txt`  
**Purpose:**  
Point-in-time snapshot of active processes and memory usage.

---

### 🌐 Networking Data
**Files:**  
`network_connections.txt`, `open_ports_lsof.txt`, `network_interfaces.txt`, `arp_cache.txt`  
**Purpose:**  
Details on open sockets, listening ports, interface IPs, and ARP cache.

---

### 📎 Persistence Mechanisms
**Folder:**  
`persistence/`  
**Contains:**  
- LaunchAgents & LaunchDaemons (system-wide and per-user)  
- Login items  
- Crontab entries (`user_crontab.txt`)

---

### 🌍 Environment Variables
**Folder:**  
`environment_vars/`  
**Purpose:**  
Captures environment variables (`printenv`) for each user and root. Useful to trace injected paths or malicious startup config.

---

### 🖱️ Browser History
**Folder:**  
`browser_history/`  
**Browsers Supported:**  
- Google Chrome  
- Microsoft Edge  
- Safari  
- Firefox (multi-profile support)  
**Purpose:**  
Historical browsing activity, timestamps, and visited URLs per user.

---

### 📜 Shell History
**Folder:**  
`user_histories/`  
**Files:**  
`.bash_history`, `.zsh_history` per user  
**Purpose:**  
Useful for tracing commands executed by each user.

---

### 📁 File Access & Malware Staging Areas
**Folder:**  
`files_recent/`  
**Scanned Locations:**  
- Downloads, Documents, LaunchAgents, `.config`, `.local`, Application Support, `tmp`, etc.  
**Purpose:**  
- Finds files modified in the last 90 days  
- Detects files flagged as `quarantined` by Gatekeeper (potential malware)

---

### 🧩 Recently Installed Applications
**Folder:**  
`recent_apps/`  
**Files:**  
- `system_applications_last90.txt`  
- `user_applications_last90.txt`  
**Purpose:**  
Lists applications installed within the past 90 days (system and user).

---

### 🔐 Security Configurations
**Files:**  
- `kernel_extensions.txt` — Loaded kernel extensions (from `kextstat`)  
- `sip_status.txt` — System Integrity Protection status (from `csrutil status`)

---

### ⏱️ Timeout Control
The script enforces a **1-hour timeout** to avoid excessive runtime. If the script runs longer than this, it will automatically terminate all child processes.

You can modify this value at the top of the script:

```bash
TIMEOUT=3600
```

## 🧪 Forensic Usage
✅ Initial compromise triage
🛠️ Internal incident response toolkit
🧾 Live evidence collection (e.g., before reimaging)
🔍 Security posture audits or threat hunting snapshots

## ⚠️ Notes
* Requires sudo privileges for complete data collection.
* Read-only: no system modifications are performed.
* Output ZIP uses relative paths for safe and clean extraction.
* Suitable for live systems — can be run remotely or interactively.

## License
MIT License — Use freely, modify as needed for internal security response use cases.
