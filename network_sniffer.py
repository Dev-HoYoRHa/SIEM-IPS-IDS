# =============================================================================
# network_sniffer.py — Sniffer réseau temps réel
# Rôle unique : capturer les paquets réseau et les transmettre au détecteur.
#
# Ce module NE fait PAS d'analyse lui-même.
# Il capture → extrait les infos → passe à intrusion_detector.analyze_event()
#
# Dépendances : pip install scapy
# Droits requis : root/admin (capture raw packets)
# =============================================================================

import time                          # Pour les timestamps des paquets

from scapy.all import sniff, IP, TCP, UDP  # Capture et décodage de paquets

from config import NETWORK_INTERFACE     # Interface réseau (config.py)
from intrusion_detector import analyze_event  # Module d'analyse
from db_manager import init_database     # Initialisation BDD au démarrage


# =============================================================================
# COMPTEUR GLOBAL (statistiques de session)
# =============================================================================
stats = {
    "total_paquets":   0,   # Nombre total de paquets capturés
    "paquets_tcp":     0,   # Paquets TCP
    "paquets_udp":     0,   # Paquets UDP
    "alertes":         0    # Nombre d'alertes déclenchées
}


# =============================================================================
# CALLBACK : traitement de chaque paquet capturé
# =============================================================================

def _traiter_paquet(paquet):
    """
    Fonction appelée automatiquement par Scapy pour chaque paquet capturé.
    Elle extrait les informations utiles et les transmet à analyze_event().

    Paramètre :
        paquet : Objet Scapy représentant un paquet réseau brut
    """
    # -------------------------------------------------------------------------
    # ÉTAPE 1 : Vérification que le paquet contient bien une couche IP
    # On ignore les paquets non-IP (ARP, STP, etc.)
    # -------------------------------------------------------------------------
    if not paquet.haslayer(IP):
        return

    # -------------------------------------------------------------------------
    # ÉTAPE 2 : Extraction des informations réseau de base
    # -------------------------------------------------------------------------
    src_ip = paquet[IP].src   # Adresse IP source
    dst_ip = paquet[IP].dst   # Adresse IP destination
    port   = 0                # Port par défaut (si ni TCP ni UDP)

    # Mise à jour du compteur global
    stats["total_paquets"] += 1

    # -------------------------------------------------------------------------
    # ÉTAPE 3 : Extraction du port selon le protocole de transport
    # -------------------------------------------------------------------------

    if paquet.haslayer(TCP):
        # TCP : on prend le port de destination (le service ciblé)
        port = paquet[TCP].dport
        stats["paquets_tcp"] += 1

    elif paquet.haslayer(UDP):
        # UDP : même logique
        port = paquet[UDP].dport
        stats["paquets_udp"] += 1

    # -------------------------------------------------------------------------
    # ÉTAPE 4 : Construction de l'événement au format attendu par analyze_event
    # -------------------------------------------------------------------------
    event = {
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "port":      port,
        "timestamp": time.time()   # Horodatage au moment de la capture
    }

    # Affichage console discret (une ligne par paquet)
    print(f"  [PAQUET] {src_ip:<16} → {dst_ip:<16}  port={port:<6}  "
          f"proto={'TCP' if paquet.haslayer(TCP) else 'UDP' if paquet.haslayer(UDP) else 'IP'}")

    # -------------------------------------------------------------------------
    # ÉTAPE 5 : Transmission au détecteur d'intrusion
    # Ce module ne fait AUCUNE analyse lui-même — il délègue entièrement.
    # -------------------------------------------------------------------------
    alerte = analyze_event(event)

    # Si une alerte a été générée, on incrémente le compteur de session
    if alerte:
        stats["alertes"] += 1


# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

def start_sniffing(interface=None, nb_paquets=0, filtre="ip"):
    """
    Démarre la capture de paquets réseau en temps réel.

    Paramètres :
        interface  (str) : Interface réseau à écouter (ex: "eth0", "wlan0")
                           Si None, utilise NETWORK_INTERFACE depuis config.py
        nb_paquets (int) : Nombre de paquets à capturer (0 = infini)
        filtre     (str) : Filtre BPF (Berkeley Packet Filter)
                           "ip"  → uniquement paquets IP (par défaut)
                           "tcp" → uniquement TCP
                           ""    → tout le trafic

    La capture tourne en boucle jusqu'à :
        - nb_paquets atteint (si > 0)
        - Interruption clavier CTRL+C
    """

    # Utilisation de l'interface par défaut si non précisée
    if interface is None:
        interface = NETWORK_INTERFACE

    print("\n" + "=" * 60)
    print(f"  SNIFFER RÉSEAU DÉMARRÉ")
    print(f"  Interface : {interface}")
    print(f"  Filtre    : '{filtre}'")
    print(f"  Limite    : {nb_paquets if nb_paquets > 0 else 'infini'} paquet(s)")
    print("  → Appuyer sur CTRL+C pour arrêter")
    print("=" * 60 + "\n")

    try:
        # -------------------------------------------------------------------
        # sniff() : fonction Scapy de capture
        #   iface   = interface réseau
        #   prn     = callback appelé pour chaque paquet
        #   filter  = filtre BPF (réduit le bruit)
        #   count   = 0 → capture infinie, sinon s'arrête après N paquets
        #   store   = False → ne stocke pas les paquets en mémoire (économie RAM)
        # -------------------------------------------------------------------
        sniff(
            iface   = interface,
            prn     = _traiter_paquet,
            filter  = filtre,
            count   = nb_paquets,
            store   = False
        )

    except KeyboardInterrupt:
        # Arrêt propre via CTRL+C
        print("\n\n[SNIFFER] Capture arrêtée par l'utilisateur.")

    except PermissionError:
        # Scapy nécessite des droits root/admin pour capturer
        print("\n[SNIFFER][ERREUR] Droits insuffisants.")
        print("  → Relancer avec : sudo python network_sniffer.py")

    except OSError as e:
        # Interface inexistante ou désactivée
        print(f"\n[SNIFFER][ERREUR] Interface '{interface}' inaccessible : {e}")
        print("  → Vérifier le nom de l'interface dans config.py")

    finally:
        # Affichage des statistiques de session, quoi qu'il arrive
        _afficher_stats()


# =============================================================================
# UTILITAIRE : Résumé de session
# =============================================================================

def _afficher_stats():
    """Affiche les statistiques de la session de capture."""
    print("\n" + "=" * 60)
    print("  RÉSUMÉ DE CAPTURE")
    print(f"  Paquets totaux  : {stats['total_paquets']}")
    print(f"  TCP             : {stats['paquets_tcp']}")
    print(f"  UDP             : {stats['paquets_udp']}")
    print(f"  Alertes générées: {stats['alertes']}")
    print("=" * 60)


# =============================================================================
# EXÉCUTION AUTONOME
# =============================================================================

if __name__ == "__main__":
    # Initialisation de la base de données avant la capture
    init_database()

    # Lancement de la capture sur l'interface définie dans config.py
    # Pour tester sans réseau réel : changer nb_paquets=10 pour limiter
    start_sniffing()
