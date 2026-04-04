# =============================================================================
# email_notifier.py — Envoi de notifications par email
# Rôle unique : envoyer des alertes de sécurité à l'administrateur via Gmail.
#
# Prérequis :
#   1. Activer la validation en 2 étapes sur le compte Gmail
#   2. Générer un "mot de passe d'application" :
#      compte.google.com → Sécurité → Mots de passe des applications
#   3. Renseigner SMTP_SENDER et SMTP_PASSWORD dans config.py
# =============================================================================

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

from config import (
    ADMIN_EMAIL,
    SMTP_SENDER,
    SMTP_PASSWORD,
    SMTP_HOST,
    SMTP_PORT
)


# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

def send_alert(subject, message, html_message=None):
    """
    Envoie un email d'alerte à l'administrateur.

    Paramètres :
        subject      (str) : Objet de l'email
        message      (str) : Corps de l'email en texte brut
        html_message (str) : Corps HTML optionnel (plus lisible)

    Retourne :
        bool : True si envoi réussi, False sinon
    """

    print(f"\n[EMAIL] Envoi d'une alerte : {subject}")

    # -------------------------------------------------------------------------
    # ÉTAPE 1 : Construction de l'email multipart
    # "alternative" = le client choisit entre texte et HTML
    # -------------------------------------------------------------------------
    email = MIMEMultipart("alternative")
    email["From"]    = SMTP_SENDER
    email["To"]      = ADMIN_EMAIL
    email["Subject"] = subject

    # -------------------------------------------------------------------------
    # ÉTAPE 2 : Ajout du corps texte brut (fallback universel)
    # -------------------------------------------------------------------------
    corps_texte = _generer_corps_texte(subject, message)
    email.attach(MIMEText(corps_texte, "plain", "utf-8"))

    # Corps HTML (généré automatiquement si non fourni)
    corps_html = html_message or _generer_corps_html(subject, message)
    email.attach(MIMEText(corps_html, "html", "utf-8"))

    # -------------------------------------------------------------------------
    # ÉTAPE 3 : Connexion SMTP avec chiffrement TLS et envoi
    # -------------------------------------------------------------------------
    try:
        serveur = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        serveur.ehlo()          # Identification auprès du serveur
        serveur.starttls()      # Activation du chiffrement TLS
        serveur.ehlo()          # Ré-identification après TLS
        serveur.login(SMTP_SENDER, SMTP_PASSWORD)

        serveur.sendmail(
            from_addr = SMTP_SENDER,
            to_addrs  = ADMIN_EMAIL,
            msg       = email.as_string()
        )
        serveur.quit()

        print(f"[EMAIL] Alerte envoyée avec succès à {ADMIN_EMAIL}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("[EMAIL][ERREUR] Authentification échouée.")
        print("  → Vérifier SMTP_SENDER et SMTP_PASSWORD dans config.py")
        print("  → Utiliser un mot de passe d'application Gmail")
        return False

    except smtplib.SMTPConnectError:
        print(f"[EMAIL][ERREUR] Connexion impossible à {SMTP_HOST}:{SMTP_PORT}")
        return False

    except smtplib.SMTPException as e:
        print(f"[EMAIL][ERREUR] Erreur SMTP : {e}")
        return False

    except OSError as e:
        print(f"[EMAIL][ERREUR] Erreur réseau : {e}")
        return False


# =============================================================================
# HELPERS : Construction des corps d'email
# =============================================================================

def _generer_corps_texte(subject, message):
    """Génère le corps texte brut de l'alerte."""
    horodatage = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
    return (
        f"=== ALERTE DE SÉCURITÉ — PME CYBERSEC ===\n\n"
        f"Sujet    : {subject}\n"
        f"Date     : {horodatage}\n"
        f"Destinataire : {ADMIN_EMAIL}\n\n"
        f"--- DÉTAIL ---\n{message}\n\n"
        f"Cet email a été généré automatiquement."
    )


def _generer_corps_html(subject, message):
    """
    Génère le corps HTML de l'alerte avec mise en forme colorée
    selon le niveau de criticité détecté dans le sujet.
    """
    horodatage = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    # Couleur et emoji selon criticité
    if "CRITICAL" in subject.upper():
        couleur = "#dc3545"
        emoji   = "🚨"
    elif "MEDIUM" in subject.upper():
        couleur = "#fd7e14"
        emoji   = "🔶"
    elif "LOW" in subject.upper():
        couleur = "#ffc107"
        emoji   = "⚠️"
    else:
        couleur = "#6c757d"
        emoji   = "📧"

    # Conversion des sauts de ligne en <br>
    message_html = message.replace("\n", "<br>")

    return f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><style>
  body       {{ font-family: Arial, sans-serif; background:#f8f9fa; margin:0; padding:20px; }}
  .container {{ max-width:600px; margin:0 auto; background:#fff; border-radius:8px;
                box-shadow:0 2px 8px rgba(0,0,0,.1); overflow:hidden; }}
  .header    {{ background:{couleur}; color:#fff; padding:20px;
                text-align:center; font-size:20px; font-weight:bold; }}
  .body      {{ padding:25px; color:#333; line-height:1.6; }}
  .detail    {{ background:#f8f9fa; border-left:4px solid {couleur};
                padding:15px; margin:20px 0; font-family:monospace; font-size:14px; }}
  .footer    {{ background:#e9ecef; padding:15px; text-align:center;
                color:#6c757d; font-size:12px; }}
</style></head>
<body>
  <div class="container">
    <div class="header">{emoji} ALERTE DE SÉCURITÉ — PME CYBERSEC</div>
    <div class="body">
      <h2 style="color:{couleur};margin-top:0">{subject}</h2>
      <p>📅 Date : <strong>{horodatage}</strong></p>
      <p>📩 Destinataire : <strong>{ADMIN_EMAIL}</strong></p>
      <h3>Détail de l'alerte :</h3>
      <div class="detail">{message_html}</div>
    </div>
    <div class="footer">Email automatique — ne pas répondre.</div>
  </div>
</body></html>"""


# =============================================================================
# HELPER : envoi rapide depuis intrusion_detector
# =============================================================================

def envoyer_alerte_intrusion(alerte_dict):
    """
    Formate et envoie une alerte générée par intrusion_detector.analyze_event().

    Paramètre :
        alerte_dict (dict) : Objet alerte retourné par analyze_event()
    """
    level       = alerte_dict.get("level", "UNKNOWN")
    attack_type = alerte_dict.get("attack_type", "UNKNOWN")
    description = alerte_dict.get("description", "")
    src_ip      = alerte_dict.get("src_ip", "N/A")
    port        = alerte_dict.get("port", "N/A")

    sujet = f"[{level}] {attack_type} détecté — IP source : {src_ip}"
    corps = (
        f"Type d'attaque  : {attack_type}\n"
        f"Niveau          : {level}\n"
        f"IP source       : {src_ip}\n"
        f"Port ciblé      : {port}\n\n"
        f"Description :\n{description}"
    )

    send_alert(sujet, corps)


# =============================================================================
# EXÉCUTION AUTONOME — Test
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  TEST : email_notifier.py")
    print("=" * 60)

    # Test d'envoi d'une alerte
    resultat = send_alert(
        subject = "[CRITICAL] Test d'alerte — PME Cybersec",
        message = (
            "Ceci est un email de test généré par le module email_notifier.py\n\n"
            "Type d'attaque  : PORT_SCAN\n"
            "Niveau          : CRITICAL\n"
            "IP source       : 192.168.1.100\n"
            "Ports scannés   : 21, 22, 23, 80, 443, 445, 3389\n\n"
            "Action recommandée : Bloquer l'IP immédiatement."
        )
    )

    if resultat:
        print("\n[TEST] Email envoyé avec succès !")
    else:
        print("\n[TEST] Échec de l'envoi — vérifier config.py")
