#!/bin/bash

# BlueTeam-Bash: Linux Log Threat Detector
# Scans for brute force attempts and suspicious sudo activity

LOG_FILE="/var/log/auth.log"
THRESHOLD=5
TMP_FILE="/tmp/suspicious_ips.txt"
SUDO_LOG="/tmp/suspicious_sudo.txt"

echo ""
echo "[+] Starting threat scan..."
echo "----------------------------------------"

# Check if auth.log exists
if [ ! -f "$LOG_FILE" ]; then
  echo "[!] Log file $LOG_FILE not found. Are you on Ubuntu/Debian?"
  exit 1
fi

# --- Brute Force Detection ---
echo "[*] Scanning for brute force login attempts..."
awk '/Failed password/ { print $(NF-3) }' "$LOG_FILE" | sort | uniq -c | sort -nr > "$TMP_FILE"

while read -r count ip; do
  if [ "$count" -gt "$THRESHOLD" ]; then
    echo "[!] $ip has $count failed login attempts"
    # Uncomment below to block IPs
    # sudo ufw deny from $ip
  fi
done < "$TMP_FILE"

# --- Sudo Abuse Detection ---
echo ""
echo "[*] Scanning for suspicious sudo activity..."
grep 'sudo:' "$LOG_FILE" | awk '{print $1, $2, $3, $9}' | sort | uniq -c | sort -nr > "$SUDO_LOG"

echo "[+] Sudo usage summary (top commands):"
cat "$SUDO_LOG" | head -5

# --- Cleanup ---
rm "$TMP_FILE" "$SUDO_LOG"
echo ""
echo "[+] Threat scan complete."
echo "----------------------------------------"
