# =============================================================================
# network_scanner.py — Scanner de réseau local
# Rôle unique : détecter toutes les machines actives sur un réseau local.
# Méthode     : requête ARP via Scapy (plus fiable que le ping sur LAN).
#
# Dépendances : pip install scapy
# Droits requis : root/admin (Scapy a besoin d'accès raw sockets)
# =============================================================================

import socket                     # Pour la résolution DNS (hostname)
from datetime import datetime     # Pour horodater le scan

# Scapy est utilisé pour les requêtes ARP — plus fiable que ICMP sur LAN
from scapy.all import ARP, Ether, srp

from config import NETWORK_RANGE, NETWORK_TIMEOUT  # Paramètres centralisés
from db_manager import init_database, save_machine  # Persistance en base


# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

def scan_network(ip_range=None):
    """
    Scanne un réseau local en envoyant des requêtes ARP broadcast.

    Principe ARP :
      → On envoie "Qui a cette IP ?" à toute la plage réseau
      → Les machines actives répondent avec leur adresse MAC
      → On en déduit les IP actives + MAC + hostname

    Paramètres :
        ip_range (str) : Plage réseau en notation CIDR (ex: "192.168.1.0/24")
                         Si None, utilise NETWORK_RANGE depuis config.py

    Retourne :
        list[dict] : Liste de machines, chaque machine = {ip, mac, hostname}
    """

    # Utilisation de la plage par défaut si non fournie
    if ip_range is None:
        ip_range = NETWORK_RANGE

    print(f"\n[SCANNER] Démarrage du scan sur : {ip_range}")
    print(f"[SCANNER] Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    # --------------------------------------------------------------------------
    # ÉTAPE 1 : Construction du paquet ARP
    # Ether(dst="ff:ff:ff:ff:ff:ff") → broadcast Ethernet (vers tout le réseau)
    # ARP(pdst=ip_range)             → demande ARP vers toute la plage IP
    # --------------------------------------------------------------------------
    paquet_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # --------------------------------------------------------------------------
    # ÉTAPE 2 : Envoi du paquet et réception des réponses
    # srp()   = Send and Receive at Layer 2 (avec trames Ethernet)
    # timeout = durée max d'attente de réponse
    # verbose = 0 pour supprimer les logs Scapy
    # --------------------------------------------------------------------------
    reponses, _ = srp(paquet_arp, timeout=NETWORK_TIMEOUT, verbose=0)

    # --------------------------------------------------------------------------
    # ÉTAPE 3 : Traitement des réponses
    # Chaque réponse contient : l'IP qui a répondu + son adresse MAC
    # --------------------------------------------------------------------------
    machines_actives = []

    for envoi, reponse in reponses:
        ip  = reponse[ARP].psrc   # IP source de la réponse ARP
        mac = reponse[Ether].src  # MAC source de la trame Ethernet

        # Résolution DNS inverse pour obtenir le hostname (peut échouer)
        hostname = _resoudre_hostname(ip)

        # Constitution du dictionnaire résultat pour cette machine
        machine = {
            "ip":       ip,
            "mac":      mac,
            "hostname": hostname
        }

        machines_actives.append(machine)

        # Affichage console immédiat (feedback en temps réel)
        print(f"  [+] {ip:<18} MAC: {mac:<20} Hôte: {hostname}")

        # Sauvegarde en base de données
        save_machine(ip, mac, hostname)

    # --------------------------------------------------------------------------
    # ÉTAPE 4 : Résumé du scan
    # --------------------------------------------------------------------------
    print("-" * 50)
    print(f"[SCANNER] {len(machines_actives)} machine(s) détectée(s) sur {ip_range}")

    return machines_actives


# =============================================================================
# FONCTIONS UTILITAIRES INTERNES
# =============================================================================

def _resoudre_hostname(ip):
    """
    Tente une résolution DNS inverse pour obtenir le nom d'hôte d'une IP.
    Retourne l'IP elle-même si la résolution échoue (pas de DNS, timeout...).

    Paramètre :
        ip (str) : Adresse IP à résoudre

    Retourne :
        str : Nom d'hôte ou l'IP si échec
    """
    try:
        # gethostbyaddr retourne (hostname, alias, ip_list)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.timeout):
        # herror = erreur de résolution (hôte inconnu)
        return ip


def afficher_resultats(machines):
    """
    Affiche un tableau formaté des machines découvertes.

    Paramètre :
        machines (list[dict]) : Liste retournée par scan_network()
    """
    if not machines:
        print("[SCANNER] Aucune machine détectée.")
        return

    print("\n" + "=" * 60)
    print(f"  {'IP':<18} {'MAC':<22} {'HOSTNAME'}")
    print("=" * 60)
    for m in machines:
        print(f"  {m['ip']:<18} {m['mac']:<22} {m['hostname']}")
    print("=" * 60)


# =============================================================================
# EXÉCUTION AUTONOME
# =============================================================================

if __name__ == "__main__":
    # Initialisation de la base avant le scan
    init_database()

    # Lancement du scan avec la plage par défaut (config.py)
    resultats = scan_network()

    # Affichage du tableau final
    afficher_resultats(resultats)
