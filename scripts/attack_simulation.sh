#!/bin/bash
# Purple Team Adversary Simulation Script against OpenCanary Decoy Ports

echo "[*] Triggering Fake HTTP Scan (Port 8080 - MITRE T1190)..."
sudo docker run --rm --net attacker_net --ip 172.18.0.99 curlimages/curl -m 5 http://172.18.0.1:8080/

echo "[*] Triggering Fake SSH Brute-Force (Port 2222 - MITRE T1110, T1021.004)..."
sudo docker run --rm -it --net attacker_net --ip 172.18.0.98 alpine sh -c "apk add --no-cache openssh-client && ssh admin@172.18.0.1 -p 2222"

echo "[*] Triggering Fake FTP Enumeration (Port 2121 - MITRE T1046)..."
sudo docker run --rm -it --net attacker_net --ip 172.18.0.97 alpine sh -c "apk add --no-cache lftp && lftp -u admin,pass123 -p 2121 172.18.0.1 -e 'ls; quit'"
