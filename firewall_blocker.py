# =============================================================================
# firewall_blocker.py — Bloqueur d'IP via le pare-feu du système
# Rôle unique : bloquer/débloquer une adresse IP via iptables (Linux)
#               ou netsh (Windows).
#
# Droits requis : root (Linux) ou Administrateur (Windows)
# =============================================================================

import subprocess    # Pour exécuter les commandes système (iptables, netsh)
import platform      # Pour détecter l'OS courant
import ipaddress     # Pour valider le format des adresses IP

from db_manager import init_database, save_blocked_ip, get_blocked_ips  # Persistance


# =============================================================================
# DÉTECTION DU SYSTÈME D'EXPLOITATION
# =============================================================================

# On détecte l'OS une seule fois au chargement du module
OS_TYPE = platform.system().lower()
# Résultat possible : "linux", "windows", "darwin" (macOS)


# =============================================================================
# FONCTION PRINCIPALE : Blocage d'une IP
# =============================================================================

def block_ip(ip, reason=None):
    """
    Bloque une adresse IP sur le pare-feu du système d'exploitation.

    Sur Linux  : ajoute une règle iptables DROP en entrée et en sortie
    Sur Windows: ajoute deux règles netsh (inbound + outbound)

    Paramètres :
        ip     (str) : Adresse IP à bloquer (ex: "192.168.1.100")
        reason (str) : Raison du blocage (pour la base de données)

    Retourne :
        bool : True si blocage réussi, False sinon
    """

    # -------------------------------------------------------------------------
    # ÉTAPE 1 : Validation du format de l'adresse IP
    # On refuse tout de suite les adresses mal formées
    # -------------------------------------------------------------------------
    if not _valider_ip(ip):
        print(f"[FIREWALL][ERREUR] Adresse IP invalide : '{ip}'")
        return False

    print(f"\n[FIREWALL] Tentative de blocage de : {ip}")
    print(f"[FIREWALL] OS détecté              : {OS_TYPE}")

    # -------------------------------------------------------------------------
    # ÉTAPE 2 : Appel de la fonction de blocage selon l'OS
    # -------------------------------------------------------------------------
    if OS_TYPE == "linux":
        succes = _bloquer_linux(ip)

    elif OS_TYPE == "windows":
        succes = _bloquer_windows(ip)

    elif OS_TYPE == "darwin":
        # macOS utilise pf (Packet Filter) — non implémenté ici
        print("[FIREWALL][ERREUR] macOS non supporté (pf non implémenté).")
        print("  → Bloquer manuellement via : sudo pfctl ...")
        return False

    else:
        print(f"[FIREWALL][ERREUR] Système non reconnu : {OS_TYPE}")
        return False

    # -------------------------------------------------------------------------
    # ÉTAPE 3 : Sauvegarde en base de données si succès
    # -------------------------------------------------------------------------
    if succes:
        save_blocked_ip(ip, reason or "Bloqué manuellement")
        print(f"[FIREWALL] ✅ IP {ip} bloquée avec succès.")
    else:
        print(f"[FIREWALL] ❌ Échec du blocage de {ip}.")

    return succes


# =============================================================================
# FONCTION : Déblocage d'une IP
# =============================================================================

def unblock_ip(ip):
    """
    Supprime les règles de blocage pour une adresse IP.

    Paramètres :
        ip (str) : Adresse IP à débloquer

    Retourne :
        bool : True si déblocage réussi, False sinon
    """

    if not _valider_ip(ip):
        print(f"[FIREWALL][ERREUR] Adresse IP invalide : '{ip}'")
        return False

    print(f"\n[FIREWALL] Déblocage de : {ip}")

    if OS_TYPE == "linux":
        succes = _debloquer_linux(ip)

    elif OS_TYPE == "windows":
        succes = _debloquer_windows(ip)

    else:
        print("[FIREWALL][ERREUR] OS non supporté pour le déblocage.")
        return False

    if succes:
        print(f"[FIREWALL] ✅ IP {ip} débloquée.")
    else:
        print(f"[FIREWALL] ❌ Échec du déblocage de {ip}.")

    return succes


# =============================================================================
# IMPLÉMENTATIONS PAR OS
# =============================================================================

def _bloquer_linux(ip):
    """
    Bloque une IP sur Linux via iptables.

    Ajoute deux règles :
        INPUT  DROP  → bloque le trafic entrant depuis cette IP
        OUTPUT DROP  → bloque le trafic sortant vers cette IP

    Paramètre : ip (str)
    Retourne  : bool
    """
    commandes = [
        # Bloquer trafic entrant depuis l'IP
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        # Bloquer trafic sortant vers l'IP
        ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
    ]

    return _executer_commandes(commandes)


def _debloquer_linux(ip):
    """
    Supprime les règles iptables de blocage pour une IP.

    Paramètre : ip (str)
    Retourne  : bool
    """
    commandes = [
        # Supprimer règle entrante
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        # Supprimer règle sortante
        ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
    ]

    return _executer_commandes(commandes)


def _bloquer_windows(ip):
    """
    Bloque une IP sur Windows via netsh advfirewall.

    Ajoute deux règles dans le pare-feu Windows :
        Une pour le trafic entrant (in)
        Une pour le trafic sortant (out)

    Paramètre : ip (str)
    Retourne  : bool
    """
    # Nom de règle unique pour pouvoir la retrouver/supprimer facilement
    nom_regle = f"CYBERSEC_BLOCK_{ip.replace('.', '_')}"

    commandes = [
        # Règle entrante
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={nom_regle}_IN",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ],
        # Règle sortante
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={nom_regle}_OUT",
            "dir=out",
            "action=block",
            f"remoteip={ip}"
        ],
    ]

    return _executer_commandes(commandes)


def _debloquer_windows(ip):
    """
    Supprime les règles netsh de blocage pour une IP.

    Paramètre : ip (str)
    Retourne  : bool
    """
    nom_regle = f"CYBERSEC_BLOCK_{ip.replace('.', '_')}"

    commandes = [
        ["netsh", "advfirewall", "firewall", "delete", "rule",
         f"name={nom_regle}_IN"],
        ["netsh", "advfirewall", "firewall", "delete", "rule",
         f"name={nom_regle}_OUT"],
    ]

    return _executer_commandes(commandes)


# =============================================================================
# UTILITAIRES INTERNES
# =============================================================================

def _executer_commandes(commandes):
    """
    Exécute une liste de commandes système et retourne True si tout réussit.

    Paramètre :
        commandes (list[list[str]]) : Liste de commandes à exécuter

    Retourne :
        bool : True si toutes les commandes ont réussi (returncode=0)
    """
    toutes_ok = True

    for cmd in commandes:
        try:
            print(f"  [FIREWALL] Exécution : {' '.join(cmd)}")

            # subprocess.run avec capture de la sortie (stdout + stderr)
            resultat = subprocess.run(
                cmd,
                capture_output = True,  # Capture stdout et stderr
                text           = True,  # Décode en UTF-8
                check          = False  # Ne lève pas d'exception sur erreur
            )

            if resultat.returncode == 0:
                print(f"  [FIREWALL] → OK")
            else:
                # Affichage du message d'erreur système
                erreur = resultat.stderr.strip() or resultat.stdout.strip()
                print(f"  [FIREWALL] → ERREUR (code {resultat.returncode}) : {erreur}")
                toutes_ok = False

        except FileNotFoundError:
            # La commande (iptables/netsh) n'est pas installée ou pas dans PATH
            print(f"  [FIREWALL][ERREUR] Commande introuvable : {cmd[0]}")
            print(f"  → Vérifier que {cmd[0]} est installé et accessible.")
            toutes_ok = False

        except PermissionError:
            print(f"  [FIREWALL][ERREUR] Droits insuffisants pour exécuter : {cmd[0]}")
            print("  → Relancer en root (Linux) ou Administrateur (Windows).")
            toutes_ok = False

    return toutes_ok


def _valider_ip(ip):
    """
    Vérifie qu'une chaîne est une adresse IPv4 valide.

    Paramètre :
        ip (str) : Chaîne à valider

    Retourne :
        bool : True si valide, False sinon
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def lister_ip_bloquees():
    """Affiche toutes les IP bloquées enregistrées en base."""
    ips = get_blocked_ips()
    if not ips:
        print("[FIREWALL] Aucune IP bloquée en base.")
        return

    print("\n" + "=" * 60)
    print(f"  {'IP':<18} {'RAISON':<25} {'DATE'}")
    print("=" * 60)
    for ip, reason, date in ips:
        print(f"  {ip:<18} {(reason or '-'):<25} {date}")
    print("=" * 60)


# =============================================================================
# EXÉCUTION AUTONOME — Test du module
# =============================================================================

if __name__ == "__main__":
    init_database()

    print("=" * 60)
    print("  TEST : firewall_blocker.py")
    print("=" * 60)

    # Test avec une IP invalide (doit être refusée)
    print("\n--- Test 1 : IP invalide ---")
    block_ip("999.999.999.999", "test invalide")

    # Test avec une IP valide (exécutera la commande système)
    print("\n--- Test 2 : Blocage d'une IP valide ---")
    ip_test = "10.0.0.99"
    block_ip(ip_test, "Test de blocage manuel")

    # Affichage de la liste des IP bloquées
    print("\n--- Test 3 : Liste des IP bloquées ---")
    lister_ip_bloquees()

    # Déblocage
    print("\n--- Test 4 : Déblocage ---")
    unblock_ip(ip_test)
