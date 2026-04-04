# =============================================================================
# intrusion_detector.py — Détecteur d'intrusion réseau
# Rôle unique : analyser des événements réseau et détecter les comportements
#               suspects (scan de ports, flood de connexions, accès sensibles).
#
# Ce module ne capture PAS le trafic lui-même — il reçoit des événements
# déjà mis en forme (dictionnaires) et les analyse.
# =============================================================================

import time                      # Pour les comparaisons temporelles
from collections import defaultdict  # Compteurs par IP sans KeyError

from config import (
    SENSITIVE_PORTS,
    PORT_SCAN_THRESHOLD,
    CONNECTION_FLOOD_THRESHOLD,
    TIME_WINDOW_SECONDS
)
from db_manager import init_database, save_event  # Persistance en base


# =============================================================================
# MÉMOIRE TEMPORAIRE (état global du module)
# Ces structures sont en mémoire vive — elles sont réinitialisées au redémarrage.
# Pour une persistance, utiliser db_manager.
# =============================================================================

# Historique des ports vus par IP source :
# { "192.168.1.100": {22, 80, 443, 8080, ...} }
historique_ports = defaultdict(set)

# Historique des timestamps de connexions par IP source :
# { "192.168.1.100": [1700000001.0, 1700000001.5, 1700000002.0, ...] }
historique_connexions = defaultdict(list)


# =============================================================================
# FONCTION PRINCIPALE D'ANALYSE
# =============================================================================

def analyze_event(event):
    """
    Analyse un événement réseau et détecte les comportements suspects.

    Format de l'événement attendu :
        {
            "src_ip":    "192.168.1.100",  # IP source (obligatoire)
            "dst_ip":    "192.168.1.1",    # IP destination (optionnelle)
            "port":      22,               # Port ciblé (optionnel)
            "timestamp": 1700000001.0      # Epoch Unix (optionnel, auto si absent)
        }

    Retourne :
        dict ou None :
            Si menace détectée → {
                "attack_type": str,   # Type d'attaque
                "level":       str,   # LOW / MEDIUM / CRITICAL
                "description": str,   # Message lisible
                "src_ip":      str,
                "dst_ip":      str,
                "port":        int
            }
            Si aucune menace → None
    """

    # -------------------------------------------------------------------------
    # ÉTAPE 1 : Extraction des champs de l'événement
    # On utilise .get() avec des valeurs par défaut pour la robustesse
    # -------------------------------------------------------------------------
    src_ip    = event.get("src_ip", "0.0.0.0")
    dst_ip    = event.get("dst_ip", "")
    port      = event.get("port", 0)
    timestamp = event.get("timestamp", time.time())  # Timestamp actuel si absent

    # -------------------------------------------------------------------------
    # ÉTAPE 2 : Nettoyage de l'historique
    # On supprime les événements plus vieux que TIME_WINDOW_SECONDS secondes
    # pour ne pas accumuler indéfiniment en mémoire
    # -------------------------------------------------------------------------
    _nettoyer_historique(src_ip, timestamp)

    # -------------------------------------------------------------------------
    # ÉTAPE 3 : Mise à jour de l'historique de cette IP
    # -------------------------------------------------------------------------

    # Ajout du port courant dans l'ensemble des ports vus par cette IP
    if port > 0:
        historique_ports[src_ip].add(port)

    # Ajout du timestamp courant dans l'historique de connexions de cette IP
    historique_connexions[src_ip].append(timestamp)

    # -------------------------------------------------------------------------
    # ÉTAPE 4 : Analyse des comportements suspects
    # On teste les 3 règles de détection dans l'ordre de priorité
    # -------------------------------------------------------------------------

    # Règle 1 : Scan de ports (CRITICAL)
    # → Une seule IP contacte trop de ports différents = scan automatisé
    if len(historique_ports[src_ip]) >= PORT_SCAN_THRESHOLD:
        return _creer_alerte(
            src_ip    = src_ip,
            dst_ip    = dst_ip,
            port      = port,
            type_att  = "PORT_SCAN",
            level     = "CRITICAL",
            desc      = (
                f"Scan de ports détecté depuis {src_ip} : "
                f"{len(historique_ports[src_ip])} ports différents contactés "
                f"en moins de {TIME_WINDOW_SECONDS}s"
            )
        )

    # Règle 2 : Flood de connexions (MEDIUM)
    # → Une IP fait trop de connexions en peu de temps = DoS ou brute-force
    nb_connexions = len(historique_connexions[src_ip])
    if nb_connexions >= CONNECTION_FLOOD_THRESHOLD:
        return _creer_alerte(
            src_ip    = src_ip,
            dst_ip    = dst_ip,
            port      = port,
            type_att  = "CONNECTION_FLOOD",
            level     = "MEDIUM",
            desc      = (
                f"Flood de connexions depuis {src_ip} : "
                f"{nb_connexions} connexions en {TIME_WINDOW_SECONDS}s"
            )
        )

    # Règle 3 : Accès à un port sensible (LOW)
    # → Connexion sur un port listé dans SENSITIVE_PORTS
    if port in SENSITIVE_PORTS:
        return _creer_alerte(
            src_ip    = src_ip,
            dst_ip    = dst_ip,
            port      = port,
            type_att  = "SENSITIVE_PORT_ACCESS",
            level     = "LOW",
            desc      = (
                f"Accès au port sensible {port} depuis {src_ip} "
                f"(service : {_nom_service(port)})"
            )
        )

    # Aucune règle déclenchée → événement normal
    return None


# =============================================================================
# FONCTIONS INTERNES
# =============================================================================

def _nettoyer_historique(src_ip, timestamp_courant):
    """
    Supprime de l'historique les connexions plus anciennes que TIME_WINDOW_SECONDS.
    Cela permet de ne détecter que les comportements récents (fenêtre glissante).

    Paramètres :
        src_ip            (str)   : IP à nettoyer
        timestamp_courant (float) : Timestamp de référence (maintenant)
    """
    limite = timestamp_courant - TIME_WINDOW_SECONDS

    # Conservation uniquement des timestamps récents
    historique_connexions[src_ip] = [
        t for t in historique_connexions[src_ip]
        if t >= limite
    ]

    # Si plus aucune connexion récente pour cette IP, on efface ses ports aussi
    if not historique_connexions[src_ip]:
        historique_ports[src_ip].clear()


def _creer_alerte(src_ip, dst_ip, port, type_att, level, desc):
    """
    Construit l'objet alerte, l'affiche en console et le sauvegarde en base.

    Paramètres :
        src_ip  (str) : IP source
        dst_ip  (str) : IP destination
        port    (int) : Port concerné
        type_att(str) : Type d'attaque
        level   (str) : Niveau LOW / MEDIUM / CRITICAL
        desc    (str) : Description lisible

    Retourne :
        dict : L'objet alerte complet
    """
    alerte = {
        "attack_type": type_att,
        "level":       level,
        "description": desc,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "port":        port
    }

    # Icône selon criticité
    icones = {"LOW": "⚠️ ", "MEDIUM": "🔶", "CRITICAL": "🚨"}
    icone = icones.get(level, "❓")

    # Affichage console coloré par niveau
    print(f"\n{icone} [{level}] ALERTE INTRUSION DÉTECTÉE")
    print(f"   Type        : {type_att}")
    print(f"   Description : {desc}")
    print(f"   Source IP   : {src_ip}  →  Destination : {dst_ip}  Port : {port}")

    # Sauvegarde en base de données
    save_event(
        src_ip      = src_ip,
        dst_ip      = dst_ip,
        port        = port,
        attack_type = type_att,
        level       = level,
        description = desc
    )

    return alerte


def _nom_service(port):
    """
    Retourne le nom courant du service pour un port donné.
    Utilisé uniquement pour les messages descriptifs.

    Paramètre :
        port (int) : Numéro de port

    Retourne :
        str : Nom du service ou "inconnu"
    """
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
        5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    return services.get(port, "inconnu")


# =============================================================================
# EXÉCUTION AUTONOME — Simulation de scénarios d'attaque
# =============================================================================

if __name__ == "__main__":
    init_database()

    print("=" * 60)
    print("  TEST : intrusion_detector.py — Simulation d'attaques")
    print("=" * 60)

    ts_base = time.time()  # Timestamp de base pour les tests

    # ----- Scénario 1 : Accès à un port sensible (LOW) -----
    print("\n--- Test 1 : Accès SSH (port 22) ---")
    event1 = {"src_ip": "10.0.0.5", "dst_ip": "192.168.1.1", "port": 22, "timestamp": ts_base}
    result = analyze_event(event1)
    if result:
        print(f"   → Résultat : {result['attack_type']} [{result['level']}]")

    # ----- Scénario 2 : Simulation d'un scan de ports (CRITICAL) -----
    print("\n--- Test 2 : Scan de ports (11 ports différents) ---")
    ports_a_scanner = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080, 8443, 1433]
    for i, p in enumerate(ports_a_scanner):
        event = {"src_ip": "10.0.0.99", "dst_ip": "192.168.1.1",
                 "port": p, "timestamp": ts_base + i * 0.5}
        result = analyze_event(event)
        if result and result["level"] == "CRITICAL":
            print(f"   → CRITIQUE détecté au port {p}")
            break

    # ----- Scénario 3 : Flood de connexions (MEDIUM) -----
    print("\n--- Test 3 : Flood de connexions (25 en 30s) ---")
    for i in range(25):
        event = {"src_ip": "10.0.0.42", "dst_ip": "192.168.1.1",
                 "port": 80, "timestamp": ts_base + i * 1.2}
        result = analyze_event(event)
        if result and result["level"] == "MEDIUM":
            print(f"   → FLOOD détecté à la connexion {i+1}")
            break
