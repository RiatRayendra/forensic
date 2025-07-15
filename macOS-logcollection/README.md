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


## 📂 Folder Tree
```text
macOS_Forensic_Collection_20250715_193712/
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
🔍 System Info
system_info.txt, hardware_info.txt, software_info.txt
→ Captures system and hardware profile for baseline analysis.

👤 User Enumeration
user_list.txt
→ Lists all users on the system.
user_activity.txt
→ Login history for each user via the last command.

🧠 Process and Memory Snapshots
running_processes.txt, top_output.txt
→ Point-in-time snapshot of active processes and memory usage.

🌐 Networking Data
network_connections.txt, open_ports_lsof.txt, network_interfaces.txt, arp_cache.txt
→ Details on open sockets, listening ports, interface IPs, and ARP cache.

📎 Persistence Mechanisms
persistence/ folder:
LaunchAgents, LaunchDaemons, login items from System and Users.

Crontab entries.

🌍 Environment Variables
environment_vars/
→ Captures shell environment of each user, useful to trace injected paths or variables.

🖱️ Browser History
browser_history/
→ History from:
Google Chrome
Microsoft Edge
Safari
Firefox (per profile)
Useful to trace user activity, visited sites, and timestamps.

📜 Shell History
user_histories/
→ .bash_history and .zsh_history from each user.

📁 File Access & Malware Staging Areas
files_recent/
→ Scans critical user folders like Downloads, Documents, Library/LaunchAgents, .config, etc., for:
Files modified in the last 90 days

Quarantined files (macOS Gatekeeper)
🧩 Recently Installed Applications
recent_apps/
→ Lists applications (both system-wide and per-user) installed in the past 90 days.

🔐 Security Configurations
kernel_extensions.txt, sip_status.txt
→ Collects loaded kernel modules and System Integrity Protection status.

⏱️ Timeout Control
The script enforces a 1-hour runtime timeout. If exceeded, it will auto-terminate all child processes to avoid infinite execution due to large systems or slow queries.

## 🧪 Forensic Usage
This script is ideal for:
Initial compromise triage
Internal incident response toolkit
Live evidence collection (e.g., prior to reimaging)
Security posture audits

## ⚠️ Notes
The script requires sudo privileges to access all users' environment and protected system areas.

ZIP compression is done with relative paths to ensure proper folder structure upon extraction.

It is safe to run on live systems — no files are modified, only read and copied.

## License
MIT License — Use freely, modify as needed for internal security response use cases.