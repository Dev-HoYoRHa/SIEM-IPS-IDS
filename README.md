# ============================================================
# PME CYBERSEC SUITE — README
# Suite de cybersécurité réseau modulaire en Python
# ============================================================

## STRUCTURE DU PROJET

cybersec_suite/

├── config.py               ← Tous les paramètres (à éditer en premier)

├── db_manager.py           ← Base de données SQLite

├── network_scanner.py      ← Scan des machines actives (ARP)

├── intrusion_detector.py   ← Détection de comportements suspects

├── network_sniffer.py      ← Capture de paquets (Scapy)

├── firewall_blocker.py     ← Blocage IP (iptables / netsh)

├── vulnerability_scanner.py← Scan de ports ouverts

├── email_notifier.py       ← Alertes email via Gmail SMTP

├── main.py                 ← Menu interactif principal

└── cybersec.db             ← Base SQLite (créée automatiquement)


## INSTALLATION

### 1. Prérequis système
- Python 3.8 ou supérieur
- Linux (recommandé) ou Windows
- Droits root/admin (requis pour Scapy et iptables/netsh)

### 2. Installation des dépendances Python

    pip install scapy

### 3. Configuration (OBLIGATOIRE)

Éditer config.py avant tout lancement :

    NETWORK_RANGE     = "192.168.X.0/24"    # Votre réseau local
    NETWORK_INTERFACE = "eth0"               # Votre interface réseau
    ADMIN_EMAIL       = "admin@domaine.com"  # Email administrateur
    SMTP_SENDER       = "vous@gmail.com"     # Compte Gmail expéditeur
    SMTP_PASSWORD     = "xxxx xxxx xxxx"     # Mot de passe d'application Gmail

Pour trouver votre interface réseau :
    Linux   : ip a   ou   ifconfig
    Windows : ipconfig


## LANCEMENT

### Programme principal (menu interactif)
    sudo python main.py          # Linux
    python main.py               # Windows (terminal Administrateur)

### Modules autonomes (test individuel)
    sudo python network_scanner.py
    sudo python network_sniffer.py
    sudo python vulnerability_scanner.py
    sudo python firewall_blocker.py
    python email_notifier.py
    python db_manager.py
    python intrusion_detector.py


## MENU PRINCIPAL

    [1] Scanner le réseau local       → Découverte ARP des machines actives
    [2] Démarrer le sniffer réseau    → Capture temps réel + détection d'intrusion
    [3] Scanner les vulnérabilités    → Ports ouverts + niveau de risque
    [4] Bloquer / Gérer les IP        → Blocage via iptables ou netsh
    [5] Envoyer un email de test      → Vérification de la config SMTP
    [6] Afficher les IP bloquées      → Liste depuis la base de données
    [7] Quitter


## FONCTIONNEMENT PAR MODULE

### network_scanner.py
- Envoie des requêtes ARP broadcast
- Récupère IP, MAC, hostname de chaque machine active
- Sauvegarde en table "machines"

### intrusion_detector.py
- Analyse les événements réseau reçus
- Détecte : scan de ports, flood de connexions, accès ports sensibles
- Niveaux : LOW / MEDIUM / CRITICAL
- Sauvegarde les alertes en table "events"

### network_sniffer.py
- Écoute l'interface réseau avec Scapy
- Extrait IP src/dst et port de chaque paquet
- Transmet à intrusion_detector.analyze_event()
- N'analyse RIEN lui-même

### firewall_blocker.py
- Linux  : ajoute règles iptables INPUT/OUTPUT DROP
- Windows: ajoute règles netsh advfirewall
- Sauvegarde en table "blocked_ips"

### vulnerability_scanner.py
- Scan TCP "connect" non agressif
- 50 threads en parallèle
- Catalogue de risques par service
- Sauvegarde en table "vulnerabilities"

### email_notifier.py
- Gmail SMTP avec TLS (port 587)
- Email texte + HTML automatique
- Couleur selon criticité (rouge/orange/jaune)

### db_manager.py
- Tables : machines, events, vulnerabilities, blocked_ips
- Fonctions save_* et get_* pour chaque table


## CONFIGURATION EMAIL GMAIL

1. Aller sur : myaccount.google.com
2. Sécurité → Validation en 2 étapes → Activer
3. Sécurité → Mots de passe des applications → Créer
4. Copier le mot de passe généré dans config.py (SMTP_PASSWORD)
   ⚠ Ne jamais utiliser votre mot de passe principal Gmail


## DROITS REQUIS

| Module                  | Linux       | Windows        |
|-------------------------|-------------|----------------|
| network_scanner.py      | root (sudo) | Administrateur |
| network_sniffer.py      | root (sudo) | Administrateur |
| firewall_blocker.py     | root (sudo) | Administrateur |
| vulnerability_scanner.py| Utilisateur | Utilisateur    |
| email_notifier.py       | Utilisateur | Utilisateur    |
| db_manager.py           | Utilisateur | Utilisateur    |


## BASE DE DONNÉES

Le fichier cybersec.db est créé automatiquement dans le répertoire du projet.
Visualiser avec DB Browser for SQLite : https://sqlitebrowser.org/

Tables créées :
- machines        : IP, MAC, hostname, date de découverte
- events          : alertes d'intrusion avec niveau et description
- vulnerabilities : ports ouverts et niveau de risque par machine
- blocked_ips     : IP bloquées avec raison et date


## DÉPANNAGE

Erreur "Permission denied" avec Scapy :
    → Lancer avec sudo (Linux) ou en Administrateur (Windows)

Erreur "No module named scapy" :
    → pip install scapy

Erreur d'authentification email :
    → Utiliser un mot de passe d'application, pas le mot de passe Gmail
    → Vérifier que la validation en 2 étapes est activée

Interface réseau introuvable :
    → Corriger NETWORK_INTERFACE dans config.py
    → Linux: ip a | grep "state UP"
    → Windows: ipconfig | findstr "adapter"
