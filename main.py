# =============================================================================
# main.py — Programme principal de la suite de cybersécurité
# Rôle unique : afficher un menu interactif et appeler les modules correspondants.
#
# Ce fichier est le point d'entrée du projet.
# Il n'effectue aucune logique de sécurité lui-même —
# il délègue entièrement à chaque module spécialisé.
# =============================================================================

import os
import sys
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Initialisation de la base de données dès le lancement
# ─────────────────────────────────────────────────────────────────────────────
from db_manager import init_database

# Import des modules fonctionnels
from network_scanner      import scan_network, afficher_resultats
from network_sniffer      import start_sniffing
from vulnerability_scanner import scan_vulnerabilities
from firewall_blocker     import block_ip, unblock_ip, lister_ip_bloquees
from email_notifier       import send_alert
from config               import NETWORK_RANGE, NETWORK_INTERFACE


# =============================================================================
# UTILITAIRES D'AFFICHAGE
# =============================================================================

def effacer_ecran():
    """Efface le terminal (compatible Linux et Windows)."""
    os.system("cls" if os.name == "nt" else "clear")


def afficher_banniere():
    """Affiche la bannière ASCII de démarrage."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        ██████╗██╗   ██╗██████╗ ███████╗██████╗              ║
║       ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗             ║
║       ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝             ║
║       ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗             ║
║       ╚██████╗   ██║   ██████╔╝███████╗██║  ██║             ║
║        ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝             ║
║                                                             ║
║          Suite de Cybersécurité : Détection d'activites 
                            suspectes                          ║
║                          Version 1.0                         ║
╚══════════════════════════════════════════════════════════════╝
""")


def afficher_menu():
    """Affiche le menu principal interactif."""
    heure = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    print(f"\n  ⏱  {heure}  |  Réseau surveillé : {NETWORK_RANGE}")
    print("─" * 60)
    print("  MENU PRINCIPAL")
    print("─" * 60)
    print("  [1]   Scanner le réseau local")
    print("  [2]   Démarrer le sniffer réseau")
    print("  [3]   Scanner les vulnérabilités")
    print("  [4]   Bloquer / Gérer les IP")
    print("  [5]   Envoyer un email de test")
    print("  [6]   Afficher les IP bloquées")
    print("  [7]   Quitter")
    print("─" * 60)


def lire_choix(prompt="  Votre choix : ", valeurs_valides=None):
    """
    Lit et valide la saisie utilisateur.

    Paramètres :
        prompt         (str)      : Message affiché avant la saisie
        valeurs_valides (list)    : Valeurs acceptées (None = tout accepter)

    Retourne :
        str : La saisie validée
    """
    while True:
        try:
            choix = input(prompt).strip()
            if valeurs_valides is None or choix in valeurs_valides:
                return choix
            else:
                print(f"  [ERREUR] Choix invalide. Options : {valeurs_valides}")
        except (EOFError, KeyboardInterrupt):
            print("\n  Interruption détectée. Retour au menu.")
            return ""


# =============================================================================
# ACTIONS DU MENU
# =============================================================================

def action_scanner_reseau():
    """Option 1 : Lance le scanner de réseau local."""
    print("\n" + "═" * 60)
    print("  SCANNER DE RÉSEAU LOCAL")
    print("═" * 60)

    # Demande de la plage réseau (utilise la valeur par défaut si vide)
    plage = input(f"  Plage IP [{NETWORK_RANGE}] : ").strip()
    if not plage:
        plage = NETWORK_RANGE

    try:
        # Appel du module de scan
        resultats = scan_network(plage)
        afficher_resultats(resultats)

        # Proposition d'alerte email si des machines sont trouvées
        if resultats:
            envoyer = input("\n  Envoyer le rapport par email ? (o/n) : ").strip().lower()
            if envoyer == "o":
                corps = f"Scan du réseau {plage} — {len(resultats)} machine(s) détectée(s) :\n\n"
                for m in resultats:
                    corps += f"  IP: {m['ip']}  MAC: {m['mac']}  Hôte: {m['hostname']}\n"
                send_alert(f"[INFO] Rapport de scan réseau — {plage}", corps)

    except Exception as e:
        print(f"  [ERREUR] Scan impossible : {e}")
        print("  → Vérifier les droits root/admin et que Scapy est installé")


def action_sniffer():
    """Option 2 : Lance le sniffer réseau en temps réel."""
    print("\n" + "═" * 60)
    print("  SNIFFER RÉSEAU TEMPS RÉEL")
    print("═" * 60)

    interface = input(f"  Interface réseau [{NETWORK_INTERFACE}] : ").strip()
    if not interface:
        interface = NETWORK_INTERFACE

    filtre = input("  Filtre BPF [ip] : ").strip()
    if not filtre:
        filtre = "ip"

    try:
        # Appel du module sniffer (tourne jusqu'à CTRL+C)
        start_sniffing(interface=interface, filtre=filtre)
    except Exception as e:
        print(f"  [ERREUR] Sniffer impossible : {e}")
        print("  → Vérifier les droits root/admin et l'interface réseau")


def action_scan_vulnerabilites():
    """Option 3 : Lance le scanner de vulnérabilités."""
    print("\n" + "═" * 60)
    print("  SCANNER DE VULNÉRABILITÉS")
    print("═" * 60)

    plage = input(f"  Plage IP [{NETWORK_RANGE}] : ").strip()
    if not plage:
        plage = NETWORK_RANGE

    print(f"\n  Démarrage du scan de vulnérabilités sur {plage}...")
    print("  (Cela peut prendre quelques minutes selon la taille du réseau)")

    try:
        rapport = scan_vulnerabilities(plage)

        # Proposition d'alerte si des vulnérabilités critiques sont trouvées
        nb_critiques = sum(
            1
            for vulns in rapport.values()
            for v in vulns
            if v.get("risk_level") in ("CRITICAL", "HIGH")
        )

        if nb_critiques > 0:
            envoyer = input(
                f"\n  {nb_critiques} vulnérabilité(s) critique(s) trouvée(s). "
                f"Envoyer un email ? (o/n) : "
            ).strip().lower()

            if envoyer == "o":
                corps = f"Scan de vulnérabilités — {plage}\n\n"
                corps += f"{nb_critiques} vulnérabilité(s) CRITIQUE(S) / HIGH détectée(s) :\n\n"
                for ip, vulns in rapport.items():
                    for v in vulns:
                        if v.get("risk_level") in ("CRITICAL", "HIGH"):
                            corps += (
                                f"  IP: {ip}  Port: {v['port']}  "
                                f"Service: {v['service']}  [{v['risk_level']}]\n"
                                f"  → {v['detail']}\n\n"
                            )
                send_alert(
                    f"[CRITICAL] Rapport de vulnérabilités — {nb_critiques} critique(s)",
                    corps
                )

    except Exception as e:
        print(f"  [ERREUR] Scan impossible : {e}")


def action_bloquer_ip():
    """Option 4 : Gestion des IP bloquées (bloquer / débloquer)."""
    print("\n" + "═" * 60)
    print("  GESTION DES IP BLOQUÉES")
    print("═" * 60)
    print("  [1] Bloquer une IP")
    print("  [2] Débloquer une IP")
    print("  [3] Retour au menu principal")

    choix = lire_choix("  Votre choix : ", ["1", "2", "3"])

    if choix == "1":
        ip     = input("  IP à bloquer   : ").strip()
        raison = input("  Raison         : ").strip() or "Blocage manuel"
        if ip:
            block_ip(ip, raison)
        else:
            print("  [ERREUR] IP vide.")

    elif choix == "2":
        ip = input("  IP à débloquer : ").strip()
        if ip:
            unblock_ip(ip)
        else:
            print("  [ERREUR] IP vide.")

    elif choix == "3":
        return


def action_test_email():
    """Option 5 : Envoie un email de test à l'administrateur."""
    print("\n" + "═" * 60)
    print("  TEST EMAIL")
    print("═" * 60)

    sujet  = input("  Sujet   [Test PME Cybersec] : ").strip() or "Test PME Cybersec"
    message = input("  Message [Test de la suite] : ").strip() or "Email de test envoyé depuis main.py"

    send_alert(sujet, message)


def action_ips_bloquees():
    """Option 6 : Affiche toutes les IP bloquées en base de données."""
    print("\n" + "═" * 60)
    print("  IP BLOQUÉES (base de données)")
    print("═" * 60)
    lister_ip_bloquees()


# =============================================================================
# BOUCLE PRINCIPALE
# =============================================================================

def main():
    """
    Point d'entrée du programme.
    Initialise la base, affiche la bannière, puis tourne en boucle
    jusqu'à ce que l'utilisateur choisisse de quitter.
    """

    # Initialisation unique de la base de données
    init_database()

    # Affichage de la bannière
    effacer_ecran()
    afficher_banniere()
    input("  Appuyer sur Entrée pour démarrer...")

    # ─── Boucle principale ───────────────────────────────────────────────────
    while True:
        effacer_ecran()
        afficher_banniere()
        afficher_menu()

        choix = lire_choix(
            prompt         = "  Votre choix : ",
            valeurs_valides = ["1", "2", "3", "4", "5", "6", "7"]
        )

        if choix == "1":
            action_scanner_reseau()

        elif choix == "2":
            action_sniffer()

        elif choix == "3":
            action_scan_vulnerabilites()

        elif choix == "4":
            action_bloquer_ip()

        elif choix == "5":
            action_test_email()

        elif choix == "6":
            action_ips_bloquees()

        elif choix == "7":
            print("\n  Au revoir. La suite PME Cybersec est arrêtée.")
            sys.exit(0)

        # Pause avant de revenir au menu (sauf pour le sniffer qui bloque)
        if choix in ["1", "3", "4", "5", "6"]:
            input("\n  Appuyer sur Entrée pour revenir au menu...")


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interruption clavier détectée. Fermeture propre.")
        sys.exit(0)
