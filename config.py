# =============================================================================
# config.py — Configuration centrale de la suite de cybersécurité
# Tous les paramètres du projet sont centralisés ici.
# Chaque module importe ce fichier pour éviter les valeurs "en dur".
# =============================================================================

# ---------------------------------------------------------------------------
# RÉSEAU
# ---------------------------------------------------------------------------

# Plage IP du réseau local à surveiller (notation CIDR)
NETWORK_RANGE = "192.168.1.0/24"

# Interface réseau à écouter pour le sniffer (ex: "eth0", "wlan0", "Wi-Fi")
NETWORK_INTERFACE = "eth0"

# Timeout en secondes pour les requêtes réseau (ping, ARP, etc.)
NETWORK_TIMEOUT = 2

# ---------------------------------------------------------------------------
# PORTS SENSIBLES
# Ports considérés comme critiques s'ils sont ouverts ou accédés.
# ---------------------------------------------------------------------------
SENSITIVE_PORTS = [
    21,    # FTP  — transfert de fichiers non chiffré
    22,    # SSH  — accès distant (légitime mais ciblé)
    23,    # Telnet — accès distant non chiffré (très dangereux)
    25,    # SMTP — messagerie (peut servir à spammer)
    53,    # DNS  — résolution de noms
    80,    # HTTP — web non chiffré
    110,   # POP3 — lecture mail non chiffrée
    135,   # RPC  — Windows RPC (vecteur d'attaque courant)
    139,   # NetBIOS — partage Windows
    143,   # IMAP — lecture mail
    443,   # HTTPS — web chiffré
    445,   # SMB  — partage de fichiers Windows (WannaCry, etc.)
    1433,  # MSSQL — base de données Microsoft
    3306,  # MySQL — base de données
    3389,  # RDP  — Bureau à distance Windows
    5900,  # VNC  — contrôle à distance
    8080,  # HTTP alternatif
    8443,  # HTTPS alternatif
]

# Ports à scanner lors du scan de vulnérabilités
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
              443, 445, 1433, 3306, 3389, 5900, 8080, 8443]

# ---------------------------------------------------------------------------
# DÉTECTION D'INTRUSION
# Seuils pour déclencher une alerte comportementale.
# ---------------------------------------------------------------------------

# Nombre de ports différents scannés depuis une même IP → détection de scan
PORT_SCAN_THRESHOLD = 10

# Nombre de connexions depuis une même IP dans la fenêtre de temps → flood
CONNECTION_FLOOD_THRESHOLD = 20

# Fenêtre de temps (en secondes) pour analyser les comportements
TIME_WINDOW_SECONDS = 60

# ---------------------------------------------------------------------------
# BASE DE DONNÉES SQLite
# ---------------------------------------------------------------------------

# Chemin vers le fichier SQLite (créé automatiquement s'il n'existe pas)
DATABASE_PATH = "cybersec.db"

# ---------------------------------------------------------------------------
# EMAIL — Notifications et alertes
# ---------------------------------------------------------------------------

# Adresse email de l'administrateur (destinataire des alertes)
ADMIN_EMAIL = "s,tp@gmail.com"

# Expéditeur Gmail utilisé pour envoyer les alertes
SMTP_SENDER = "azerty@gmail.com"

# Mot de passe d'application Gmail (pas le mot de passe principal !)
# Générer via : compte Google → Sécurité → Mots de passe des applications
SMTP_PASSWORD = "0146876"

# Serveur SMTP Gmail
SMTP_HOST = "smtp.gmail.com"

# Port SMTP avec chiffrement TLS
SMTP_PORT = 587
