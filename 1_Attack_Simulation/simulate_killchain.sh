#!/bin/bash
# Script de simulation Cyber Kill Chain (Network + App)
# Il utilise la commande 'logger' pour écrire dans les logs système standards.

# IP de l'attaquant simulé (Une IP qui n'est pas la tienne)
ATTACKER_IP="192.168.66.6"

echo "🔥 Démarrage de la Cyber Kill Chain..."

# ---------------------------------------------------------
# PHASE 1 : RECONNAISSANCE (Scan de Ports type Nmap)
# ---------------------------------------------------------
echo "📡 [PHASE 1] Simulation d'un Scan de Ports (Nmap)..."
# On simule un scan sur les ports 20 à 30, plus 80 et 443
for port in {20..30} 80 443; do
    # On simule un log de pare-feu (UFW) rejetant une connexion
    # Cela va s'écrire dans /var/log/syslog
    logger -t kernel "[UFW BLOCK] IN=eth0 OUT= MAC=00:00 SRC=$ATTACKER_IP DST=192.168.1.10 PROTO=TCP DPT=$port"
    sleep 0.1
done

# ---------------------------------------------------------
# PHASE 2 : INTRUSION (Brute Force SSH type Hydra)
# ---------------------------------------------------------
echo "🔨 [PHASE 2] Simulation d'un Brute Force SSH..."
# On simule 15 tentatives de mot de passe ratées
for i in {1..15}; do
    # On utilise $RANDOM pour le port source pour éviter que Linux ne groupe les logs
    # Cela va s'écrire dans /var/log/auth.log
    logger -p auth.info -t sshd "Failed password for invalid user admin from $ATTACKER_IP port $RANDOM ssh2"
    sleep 0.2
done

echo "✅ Attaque terminée. Vérifie Splunk et ton IDS !"
