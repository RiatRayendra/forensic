#!/bin/bash
# Final macOS Mseries Forensic Script - Enhanced All User Support
# Author: Riat Rayendra

# Manual timeout: kill script after 3600 seconds (1 hour)
TIMEOUT=3600  # seconds
TIMER_PID_FILE="/tmp/forensic_script_timer.pid"

timeout_kill() {
  echo "[!] ⏰ Timeout reached ($TIMEOUT seconds). Terminating script..."
  pkill -P $$  # Kill all child processes
  exit 124
}

# Set trap to clean up
cleanup() {
  [ -f "$TIMER_PID_FILE" ] && kill "$(cat "$TIMER_PID_FILE")" 2>/dev/null && rm -f "$TIMER_PID_FILE"
}
trap cleanup EXIT

# Start background timer
(
  sleep "$TIMEOUT"
  timeout_kill
) &
echo $! > "$TIMER_PID_FILE"

OUTDIR="/tmp/macOS_Forensic_Collection_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR" "$OUTDIR/browser_history" "$OUTDIR/files_recent" "$OUTDIR/recent_apps" "$OUTDIR/persistence" "$OUTDIR/user_histories" "$OUTDIR/environment_vars"

log() {
  echo "[+] $1"
}

# Get all local human users
get_users() {
  dscl . list /Users | grep -v '^_' | while read user; do
    home=$(dscl . read /Users/$user NFSHomeDirectory 2>/dev/null | cut -d ' ' -f2-)
    if [ -d "$home" ]; then
      echo "$user:$home"
    fi
  done
}

# ---------------------
# SYSTEM INFO
# ---------------------
log "Collecting system info..."
uname -a > "$OUTDIR/system_info.txt"
system_profiler SPHardwareDataType > "$OUTDIR/hardware_info.txt"
system_profiler SPSoftwareDataType > "$OUTDIR/software_info.txt"

# ---------------------
# USER ACTIVITY
# ---------------------
log "Collecting user info and login history..."
dscl . list /Users > "$OUTDIR/user_list.txt"
for entry in $(get_users); do
  IFS=":" read user home <<< "$entry"
  echo "User: $user" >> "$OUTDIR/user_activity.txt"
  last $user >> "$OUTDIR/user_activity.txt"
  echo "---" >> "$OUTDIR/user_activity.txt"
done

# ---------------------
# NETWORK & PROCESS
# ---------------------
log "Collecting process and network info..."
ps auxww > "$OUTDIR/running_processes.txt"
top -l 1 > "$OUTDIR/top_output.txt"
netstat -anv > "$OUTDIR/network_connections.txt"
lsof -i -n > "$OUTDIR/open_ports_lsof.txt"
ifconfig -a > "$OUTDIR/network_interfaces.txt"
arp -a > "$OUTDIR/arp_cache.txt"

# ---------------------
# PERSISTENCE & ENV
# ---------------------
log "Collecting persistence mechanisms..."
launchctl list > "$OUTDIR/persistence/launchctl_list.txt"
ls /Library/LaunchAgents > "$OUTDIR/persistence/system_launch_agents.txt" 2>/dev/null
ls /Library/LaunchDaemons > "$OUTDIR/persistence/system_launch_daemons.txt" 2>/dev/null
crontab -l > "$OUTDIR/user_crontab.txt" 2>/dev/null
osascript -e 'tell application "System Events" to get the name of every login item' > "$OUTDIR/login_items.txt"
mkdir -p "$OUTDIR/environment_vars"
for entry in $(get_users); do
  IFS=":" read user home <<< "$entry"
  log "  ↳ Collecting env for user: $user"
  sudo -H -u "$user" printenv > "$OUTDIR/environment_vars/${user}_env.txt" 2>/dev/null
done
log "  ↳ Collecting env for root"
sudo printenv > "$OUTDIR/environment_vars/root_env.txt" 2>/dev/null

# ---------------------
# COLLECT SHELL HISTORY & FILE ACTIVITY FOR ALL USERS (INCLUDING ROOT)
# ---------------------
log "Collecting shell history and file activity for all users including root..."

for entry in $(get_users); do
  IFS=":" read user home <<< "$entry"
  log "  ↳ Processing user: $user"

  # Buat folder output khusus untuk user ini
  user_dir="$OUTDIR/files_recent/$user"
  mkdir -p "$user_dir"

  # Bash History
  if [ -f "$home/.bash_history" ]; then
    cp "$home/.bash_history" "$OUTDIR/user_histories/${user}_bash_history.txt"
  else
    echo "[!] No .bash_history for $user" > "$OUTDIR/user_histories/${user}_bash_history.txt"
  fi

  # Zsh History
  if [ -f "$home/.zsh_history" ]; then
    cp "$home/.zsh_history" "$OUTDIR/user_histories/${user}_zsh_history.txt"
  else
    echo "[!] No .zsh_history for $user" > "$OUTDIR/user_histories/${user}_zsh_history.txt"
  fi

  # Folder umum malware
  suspicious_dirs=( "Downloads" "Documents" "Library/LaunchAgents" ".config" ".local" "Library/Application Support" "tmp" )

  for dir in "${suspicious_dirs[@]}"; do
    target="$home/$dir"
    safe_name=$(echo "$dir" | tr '/' '_')

    if [ -d "$target" ]; then
      log "    ↳ Scanning $dir for recent files..."

      # File baru
      find "$target" -maxdepth 3 -type f -mtime -90 -ls >> "$user_dir/${safe_name}_last90.txt" 2>/dev/null

      # Quarantine files
      find "$target" -maxdepth 3 -type f -mtime -90 -exec sh -c '
        for f; do
          if xattr "$f" 2>/dev/null | grep -q "com.apple.quarantine"; then
            echo "$f"
          fi
        done
      ' sh {} + >> "$user_dir/filestree_files.txt" 2>/dev/null
    fi
  done
done

# ---------------------
# SYSTEM /tmp ANALYSIS
# ---------------------
log "Scanning system-wide /tmp and /private/tmp directories..."
mkdir -p "$OUTDIR/files_recent/_system"

# 1. Scan /tmp (symlink)
find /tmp -maxdepth 3 -type f -ls >> "$OUTDIR/files_recent/_system/tmp_last90_symlink.txt" 2>/dev/null
find /tmp -maxdepth 3 -type f -exec sh -c '
  for f; do
    if xattr "$f" 2>/dev/null | grep -q "com.apple.quarantine"; then
      echo "$f"
    fi
  done
' sh {} + >> "$OUTDIR/files_recent/_system/tmp_filestree_symlink.txt" 2>/dev/null

# 2. Scan /private/tmp (real target)
find /private/tmp -maxdepth 3 -type f -ls >> "$OUTDIR/files_recent/_system/tmp_last90_real.txt" 2>/dev/null
find /private/tmp -maxdepth 3 -type f -exec sh -c '
  for f; do
    if xattr "$f" 2>/dev/null | grep -q "com.apple.quarantine"; then
      echo "$f"
    fi
  done
' sh {} + >> "$OUTDIR/files_recent/_system/tmp_filestree_real.txt" 2>/dev/null

# ---------------------
# SYSTEM /var/log ANALYSIS
# ---------------------
log "Scanning /var/log directory (recent + quarantined files)..."

# Buat direktori output jika belum ada
mkdir -p "$OUTDIR/files_recent/_system"

# File biasa yang dimodifikasi dalam 90 hari
find /var/log -maxdepth 2 -type f -mtime -90 -ls >> "$OUTDIR/files_recent/_system/var_log_last90.txt" 2>/dev/null

# File dengan flag quarantine
find /var/log -maxdepth 2 -type f -mtime -90 -exec sh -c '
  for f; do
    if xattr "$f" 2>/dev/null | grep -q "com.apple.quarantine"; then
      echo "$f"
    fi
  done
' sh {} + >> "$OUTDIR/files_recent/_system/var_log_quarantined.txt" 2>/dev/null

# ---------------------
# BROWSER HISTORY FOR ALL USERS
# ---------------------
log "Collecting browser history from all users..."

for entry in $(get_users); do
  IFS=":" read user home <<< "$entry"

  # Chrome
  chrome_db="$home/Library/Application Support/Google/Chrome/Default/History"
  if [ -f "$chrome_db" ]; then
    log "Extracting Chrome history for $user"
    temp_db="/tmp/${user}_chrome_temp.db"
    cp "$chrome_db" "$temp_db"
    sqlite3 "$temp_db" <<EOF > "$OUTDIR/browser_history/${user}_chrome_history.txt"
.mode list
.separator " ù "
SELECT 
  '$user',
  datetime(last_visit_time/1000000-11644473600,'unixepoch'),
  url,
  title
FROM urls
ORDER BY last_visit_time DESC;
EOF
    rm -f "$temp_db"
  fi

  # Edge
  edge_db="$home/Library/Application Support/Microsoft Edge/Default/History"
  if [ -f "$edge_db" ]; then
    log "Extracting Edge history for $user"
    temp_db="/tmp/${user}_edge_temp.db"
    cp "$edge_db" "$temp_db"
    sqlite3 "$temp_db" <<EOF > "$OUTDIR/browser_history/${user}_edge_history.txt"
.mode list
.separator " ù "
SELECT 
  '$user',
  datetime(last_visit_time/1000000-11644473600,'unixepoch'),
  url,
  title
FROM urls
ORDER BY last_visit_time DESC;
EOF
    rm -f "$temp_db"
  fi

  # Safari
  safari_db="$home/Library/Safari/History.db"
  if [ -f "$safari_db" ]; then
    log "Extracting Safari history for $user"
    temp_db="/tmp/${user}_safari_temp.db"
    cp "$safari_db" "$temp_db"
    sqlite3 "$temp_db" <<EOF > "$OUTDIR/browser_history/${user}_safari_history.txt"
.mode list
.separator " ù "
SELECT 
  '$user',
  datetime(visit_time + 978307200,'unixepoch'),
  url,
  title
FROM history_visits
JOIN history_items ON history_items.id = history_visits.history_item
ORDER BY visit_time DESC;
EOF
    rm -f "$temp_db"
  fi

  # Firefox (multiple profiles)
  ff_base="$home/Library/Application Support/Firefox/Profiles"
  if [ -d "$ff_base" ]; then
    for profile in "$ff_base"/*.default*; do
      ff_db="$profile/places.sqlite"
      if [ -f "$ff_db" ]; then
        profile_name=$(basename "$profile")
        log "Extracting Firefox history for $user ($profile_name)"
        temp_db="/tmp/${user}_${profile_name}_ff_temp.db"
        cp "$ff_db" "$temp_db"
        sqlite3 "$temp_db" <<EOF >> "$OUTDIR/browser_history/${user}_firefox_history.txt"
.mode list
.separator " ù "
SELECT 
  '$user',
  datetime(visit_date/1000000,'unixepoch'),
  url,
  title
FROM moz_places
JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
ORDER BY visit_date DESC;
EOF
        rm -f "$temp_db"
      fi
    done
  fi
done


# ---------------------
# RECENTLY INSTALLED APPS
# ---------------------
log "Collecting apps installed in the last 90 days..."
find /Applications -type d -iname "*.app" -mtime -90 -exec stat -f "%Sm %N" {} + > "$OUTDIR/recent_apps/system_applications_last90.txt" 2>/dev/null
find /Users/*/Applications -type d -iname "*.app" -mtime -90 -exec stat -f "%Sm %N" {} + > "$OUTDIR/recent_apps/user_applications_last90.txt" 2>/dev/null

# ---------------------
# SECURITY CONFIGS
# ---------------------
log "Collecting SIP and kext info..."
kextstat > "$OUTDIR/kernel_extensions.txt"
csrutil status > "$OUTDIR/sip_status.txt" 2>/dev/null

# ---------------------
# FINALIZE
# ---------------------
log "Compressing result into zip file..."
cd "$(dirname "$OUTDIR")"
zip -r "$(basename "$OUTDIR").zip" "$(basename "$OUTDIR")" >/dev/null

log "Cleaning up working directory..."
rm -rf "$OUTDIR"

log "✅ Collection complete."
echo "📦 Output file: $(realpath "${OUTDIR}.zip")"
