# 🛡️ SOC Automation Project : From Attack to Response

## 📋 Présentation
Ce projet est une démonstration complète d'un pipeline de cybersécurité (DevSecOps), simulant un environnement **SOC (Security Operations Center)**.

Il intègre les trois piliers de la défense active :
1.  **Red Teaming** : Simulation d'attaques (Scan de ports & Brute Force SSH).
2.  **Blue Teaming (SIEM)** : Ingestion et visualisation des logs en temps réel avec **Splunk**.
3.  **SOAR (Automation)** : Script Python autonome pour l'analyse comportementale et l'enrichissement via Threat Intelligence (VirusTotal).

## 🏗️ Architecture
* **Attaquant :** Script Bash (`logger`, `hydra` simulation).
* **Victime/Serveur :** Environnement Linux (Ubuntu/WSL).
* **Collecteur :** Splunk Universal Forwarder.
* **Cerveau (SOAR) :** Python 3 + API VirusTotal + Pandas.

## 🚀 Fonctionnalités Clés
* [x] **Ingestion de logs Temps Réel** (Syslog & Auth.log).
* [x] **Tableau de bord Splunk** avec détection d'anomalies (XML personnalisé).
* [x] **Moteur de détection Hybride** : Analyse comportementale + Réputation IP.
* [x] **Reporting Automatisé** : Génération de tickets HTML avec score de risque.

## 📂 Structure du projet
* `1_Attack_Simulation/` : Scripts pour générer du trafic malveillant (Cyber Kill Chain).
* `2_SIEM_Splunk_Config/` : Fichiers de configuration du Forwarder et Code XML du Dashboard.
* `3_SOAR_Python_Engine/` : Le script Python de détection et réponse.

## 📸 Screenshots
*(Ajouter ici des captures d'écran du Dashboard Splunk et du Ticket HTML)*

## 🛠️ Installation
1.  Installer Splunk Universal Forwarder sur la machine Linux.
2.  Configurer l'écoute sur le port 9997 (Splunk Enterprise).
3.  Lancer le moteur SOAR : `python3 soar_engine.py`
4.  Lancer l'attaque : `bash simulate_killchain.sh`

---
*Projet réalisé dans le cadre d'un Lab de Cybersécurité Avancée.*
