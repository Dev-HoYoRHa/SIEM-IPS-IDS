# =============================================================================
# db_manager.py — Gestionnaire de base de données SQLite
# Rôle unique : créer les tables et enregistrer les événements, machines,
#               vulnérabilités et IP bloquées.
# Ce module peut être importé par tous les autres modules du projet.
# =============================================================================

import sqlite3       # Module natif Python pour SQLite
import datetime      # Pour horodater les enregistrements
import os            # Pour vérifier l'existence du fichier DB

from config import DATABASE_PATH  # Chemin vers le fichier .db


# =============================================================================
# INITIALISATION — Création de la base et des tables
# =============================================================================

def init_database():
    """
    Crée le fichier SQLite et toutes les tables nécessaires.
    Utilise IF NOT EXISTS pour être idempotent (appelable plusieurs fois).
    Retourne True si succès, False sinon.
    """
    try:
        # Ouverture (ou création) du fichier de base de données
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # ------------------------------------------------------------------
        # TABLE : machines
        # Stocke les machines découvertes lors des scans réseau.
        # ------------------------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS machines (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                mac         TEXT,
                hostname    TEXT,
                discovered_at TEXT DEFAULT (datetime('now'))
            )
        """)

        # ------------------------------------------------------------------
        # TABLE : events
        # Stocke les événements suspects détectés par intrusion_detector.
        # ------------------------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip      TEXT NOT NULL,
                dst_ip      TEXT,
                port        INTEGER,
                attack_type TEXT,
                level       TEXT,
                description TEXT,
                detected_at TEXT DEFAULT (datetime('now'))
            )
        """)

        # ------------------------------------------------------------------
        # TABLE : vulnerabilities
        # Stocke les vulnérabilités détectées par vulnerability_scanner.
        # ------------------------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                port        INTEGER,
                service     TEXT,
                risk_level  TEXT,
                detail      TEXT,
                scanned_at  TEXT DEFAULT (datetime('now'))
            )
        """)

        # ------------------------------------------------------------------
        # TABLE : blocked_ips
        # Stocke les IP bloquées par firewall_blocker.
        # ------------------------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL UNIQUE,
                reason      TEXT,
                blocked_at  TEXT DEFAULT (datetime('now'))
            )
        """)

        # Validation de toutes les créations de tables
        conn.commit()
        conn.close()

        print(f"[DB] Base de données initialisée : {DATABASE_PATH}")
        return True

    except sqlite3.Error as e:
        print(f"[DB][ERREUR] Impossible d'initialiser la base : {e}")
        return False


# =============================================================================
# FONCTIONS D'ENREGISTREMENT
# =============================================================================

def save_machine(ip, mac=None, hostname=None):
    """
    Enregistre une machine découverte dans la table 'machines'.

    Paramètres :
        ip       (str) : Adresse IP de la machine
        mac      (str) : Adresse MAC (optionnelle)
        hostname (str) : Nom d'hôte (optionnel)

    Retourne : True si succès, False sinon
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Insertion de la machine avec horodatage automatique
        cursor.execute("""
            INSERT INTO machines (ip, mac, hostname)
            VALUES (?, ?, ?)
        """, (ip, mac, hostname))

        conn.commit()
        conn.close()
        print(f"[DB] Machine enregistrée : {ip}")
        return True

    except sqlite3.Error as e:
        print(f"[DB][ERREUR] save_machine({ip}) : {e}")
        return False


def save_event(src_ip, dst_ip=None, port=None,
               attack_type=None, level=None, description=None):
    """
    Enregistre un événement suspect dans la table 'events'.

    Paramètres :
        src_ip      (str) : IP source de l'événement
        dst_ip      (str) : IP destination (optionnelle)
        port        (int) : Port concerné (optionnel)
        attack_type (str) : Type d'attaque détectée
        level       (str) : Niveau de criticité (LOW/MEDIUM/CRITICAL)
        description (str) : Description textuelle de l'alerte

    Retourne : True si succès, False sinon
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO events (src_ip, dst_ip, port, attack_type, level, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (src_ip, dst_ip, port, attack_type, level, description))

        conn.commit()
        conn.close()
        print(f"[DB] Événement enregistré : [{level}] {attack_type} depuis {src_ip}")
        return True

    except sqlite3.Error as e:
        print(f"[DB][ERREUR] save_event({src_ip}) : {e}")
        return False


def save_vulnerability(ip, port, service=None, risk_level=None, detail=None):
    """
    Enregistre une vulnérabilité détectée dans la table 'vulnerabilities'.

    Paramètres :
        ip         (str) : IP de la machine vulnérable
        port       (int) : Port ouvert concerné
        service    (str) : Nom du service (ex: SSH, FTP)
        risk_level (str) : Niveau de risque (LOW/MEDIUM/HIGH)
        detail     (str) : Détail de la vulnérabilité

    Retourne : True si succès, False sinon
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO vulnerabilities (ip, port, service, risk_level, detail)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, port, service, risk_level, detail))

        conn.commit()
        conn.close()
        print(f"[DB] Vulnérabilité enregistrée : {ip}:{port} ({service})")
        return True

    except sqlite3.Error as e:
        print(f"[DB][ERREUR] save_vulnerability({ip}:{port}) : {e}")
        return False


def save_blocked_ip(ip, reason=None):
    """
    Enregistre une IP bloquée dans la table 'blocked_ips'.
    Utilise INSERT OR IGNORE pour éviter les doublons (UNIQUE sur ip).

    Paramètres :
        ip     (str) : Adresse IP bloquée
        reason (str) : Raison du blocage (optionnelle)

    Retourne : True si succès, False sinon
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # INSERT OR IGNORE : si l'IP est déjà bloquée, on ne plante pas
        cursor.execute("""
            INSERT OR IGNORE INTO blocked_ips (ip, reason)
            VALUES (?, ?)
        """, (ip, reason))

        conn.commit()
        conn.close()
        print(f"[DB] IP bloquée enregistrée : {ip}")
        return True

    except sqlite3.Error as e:
        print(f"[DB][ERREUR] save_blocked_ip({ip}) : {e}")
        return False


# =============================================================================
# FONCTIONS DE LECTURE (utilitaires)
# =============================================================================

def get_all_events():
    """Retourne tous les événements enregistrés, du plus récent au plus ancien."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY detected_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        print(f"[DB][ERREUR] get_all_events : {e}")
        return []


def get_blocked_ips():
    """Retourne la liste de toutes les IP actuellement bloquées."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT ip, reason, blocked_at FROM blocked_ips")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        print(f"[DB][ERREUR] get_blocked_ips : {e}")
        return []


# =============================================================================
# EXÉCUTION AUTONOME — Test du module
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  TEST : db_manager.py")
    print("=" * 60)

    # Initialisation de la base
    init_database()

    # Tests d'insertion
    save_machine("192.168.1.10", "AA:BB:CC:DD:EE:FF", "serveur-web")
    save_event("192.168.1.100", "192.168.1.1", 22,
               "PORT_SCAN", "CRITICAL", "Scan de port SSH détecté")
    save_vulnerability("192.168.1.10", 23, "Telnet", "HIGH",
                       "Telnet est actif — protocole non chiffré dangereux")
    save_blocked_ip("192.168.1.100", "Scan de port détecté")

    # Affichage des événements
    print("\n[DB] Événements en base :")
    for row in get_all_events():
        print(" ", row)

    print("\n[DB] IP bloquées :")
    for row in get_blocked_ips():
        print(" ", row)
