#!/bin/bash

LOG_FILE="/var/log/auth.log"
THRESHOLD=5
TMP_FILE="/tmp/suspicious_ips.txt"

echo "[+] Scanning $LOG_FILE for failed login attempts..."

awk '/Failed password/ { print $(NF-3) }' $LOG_FILE | sort | uniq -c | sort -nr > $TMP_FILE

while read count ip; do
  if [ "$count" -gt "$THRESHOLD" ]; then
    echo "[!] Suspicious activity from $ip: $count failed attempts"
    # Uncomment below to block IP (for demo, we keep it safe)
    # sudo ufw deny from $ip
  fi
done < $TMP_FILE

rm $TMP_FILE
echo "[+] Scan complete."
