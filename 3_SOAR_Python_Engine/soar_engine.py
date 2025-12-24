import time
import re
import subprocess
import select
import requests
import pandas as pd
from datetime import datetime

# --- CONFIGURATION ---
LOG_FILES = ['/var/log/syslog', '/var/log/auth.log']
VT_API_KEY = "6962fe15db4a506e050c3dc3b748802c6e0325aba01f9eeb91f0f1475b10b9fd"  # <--- Mets ta clé ici !
WINDOW_SECONDS = 30
THRESHOLD_BRUTE = 5

class SOAR:
    def __init__(self):
        self.ip_cache = {} # Pour ne pas vérifier 100 fois la même IP sur VirusTotal

    # MODULE 1 : CTI (Intelligence)
    def check_virustotal(self, ip):
        if ip in self.ip_cache: return self.ip_cache[ip] # Déjà vérifié
        
        # Simulation pour l'IP locale (VirusTotal ne connait pas 192.168...)
        if ip.startswith("192.168.") or ip.startswith("172."):
            return {"score": 0, "country": "LAN (Local)"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                result = {"score": data['last_analysis_stats']['malicious'], "country": data.get('country', 'XX')}
                self.ip_cache[ip] = result
                return result
        except:
            pass
        return {"score": 0, "country": "Unknown"}

    # MODULE 2 : REPORTING
    def generate_ticket(self, ip, attack_type, count, cti_data):
        filename = f"TICKET_{ip.replace('.', '_')}_{int(time.time())}.html"
        html = f"""
        <html>
        <body style="font-family: sans-serif; padding: 20px; background: #f0f0f0;">
            <div style="background: white; padding: 20px; border-radius: 10px; border-left: 10px solid #e74c3c;">
                <h1 style="color: #c0392b;">🚨 ALERTE SOC : {attack_type}</h1>
                <p><strong>IP Attaquant :</strong> {ip}</p>
                <p><strong>Volume :</strong> {count} événements détectés</p>
                <hr>
                <h3>🌍 Cyber Threat Intelligence (CTI)</h3>
                <p>VirusTotal Score : <strong>{cti_data['score']}/90</strong></p>
                <p>Origine : {cti_data['country']}</p>
                <hr>
                <h3>🛡️ Action Automatique</h3>
                <p>Statut : <span style="color:green; font-weight:bold;">TICKET CRÉÉ / IP SURVEILLÉE</span></p>
                <p>Date : {datetime.now()}</p>
            </div>
        </body>
        </html>
        """
        with open(filename, "w") as f:
            f.write(html)
        print(f"📄 [SOAR] Ticket généré : {filename}")

def start_engine():
    soar = SOAR()
    buffer = []
    start_time = time.time()
    
    print(f"🤖 SOAR Engine Démarré. En attente d'attaques...")

    process = subprocess.Popen(['tail', '-F', '-n', '0'] + LOG_FILES, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    poll_obj = select.poll()
    poll_obj.register(process.stdout, select.POLLIN)

    while True:
        if poll_obj.poll(100):
            line = process.stdout.readline().decode('utf-8', errors='ignore').strip()
            
            # --- PHASE D'INGESTION ---
            if "Failed password" in line:
                match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    buffer.append({'ip': match.group(1), 'type': 'SSH_BRUTE'})
                    print(f"⚡ Détection SSH : {match.group(1)}")

            elif "UFW BLOCK" in line:
                match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    buffer.append({'ip': match.group(1), 'type': 'PORT_SCAN'})

        # --- PHASE D'ANALYSE (Toutes les 30s) ---
        if time.time() - start_time >= WINDOW_SECONDS:
            if buffer:
                df = pd.DataFrame(buffer)
                # On compte les attaques par IP
                attack_counts = df['ip'].value_counts()

                for ip, count in attack_counts.items():
                    if count >= THRESHOLD_BRUTE:
                        print(f"\n--- 🧠 ANALYSE SOAR POUR {ip} ---")
                        
                        # 1. Appel API (CTI)
                        cti_info = soar.check_virustotal(ip)
                        print(f"🌍 CTI : Score Malveillant {cti_info['score']}")

                        # 2. Décision & Reporting
                        attack_type = df[df['ip'] == ip]['type'].iloc[0]
                        soar.generate_ticket(ip, attack_type, count, cti_info)
                
                buffer = []
            start_time = time.time()

if __name__ == "__main__":
    start_engine()
