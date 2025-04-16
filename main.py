#!/usr/bin/env python3

# HookSandeer - 2025

from scapy.all import sniff, ARP
import os
from email.message import EmailMessage


FROM_EMAIL = "antonin.michon39@gmail.com"
TO_EMAIL = "antonin.michon39@gmail.com"
SMTP_COMMAND = "/usr/bin/msmtp"


mac_ip_map = {}  # Association des @MAC avec les @IP


def send_email(subject, body):
    """
    Envoie un email avec le sujet et le corps spécifiés.
    """
    msg = EmailMessage()
    msg['From'] = FROM_EMAIL
    msg['To'] = TO_EMAIL
    msg['Subject'] = subject
    msg.set_content(body)

    with os.popen(f'{SMTP_COMMAND} -t', 'w') as smtp:
        smtp.write(msg.as_string())

def arp_spoof_detection(pkt):
    """
    Fonction de détection d'ARP Spoofing.
    Elle est appelée pour chaque paquet ARP capturé.
    """
    if pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        print("Ajout de {} associé à {}".format(src_ip, src_mac))

        # Vérifier si la MAC existe déjà dans mac_ip_map
        if src_mac in mac_ip_map:
            if src_ip not in mac_ip_map[src_mac]:
                # Si la même MAC est associée à une IP différente
                print(f"ALERTE: Usurpation ARP détectée! MAC: {src_mac} -> IPs: {', '.join(mac_ip_map[src_mac])}, {src_ip}")
                subject = "🛑 ALERTE ARP Spoofing détectée !"
                body = (f"Une adresse MAC est utilisée pour plusieurs IP sur DMZ B !\n\n"
                        f"MAC : {src_mac}\n"
                        f"IPs détectées : {', '.join(mac_ip_map[src_mac])}, {src_ip}\n\n"
                        "Attaque ARP Spoofing potentielle.\n"
                        "Vérification de ServB recommandée.\n")
                print("[!] Conflit détecté ! Envoi d'un mail...")
                send_email(subject, body)
        else:
            # Ajouter la nouvelle correspondance MAC => IP
            mac_ip_map[src_mac] = [src_ip]

        # Si la MAC est déjà présente, on ajoute la nouvelle IP à la liste
        if src_mac in mac_ip_map:
            if src_ip not in mac_ip_map[src_mac]:
                mac_ip_map[src_mac].append(src_ip)
        
        # Afficher les informations de chaque paquet ARP
        print(f"ARP paquet détecté: {pkt.summary()}")
        print(f"Source IP: {src_ip}")
        print(f"Source MAC: {src_mac}")
        print(f"Destination IP: {pkt[ARP].pdst}")
        print(f"Destination MAC: {pkt[ARP].hwdst}")
        print("----")

# Lancement du sniff en continu
print("👀 Surveillance du réseau en cours (Ctrl+C pour quitter)...")
sniff(iface="enxf8e43b1ca672", filter="arp", store=False, prn=arp_spoof_detection)
