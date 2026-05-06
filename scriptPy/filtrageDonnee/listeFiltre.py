import sys
import os

# Remonte d'un niveau pour atteindre la racine du projet
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from LectureDonne import optionsArgParse as options
import ipaddress

def filtre_Selectionner() :
    """
    Récupère les données des champs de filtres sélectionnés par l'utilisateur.
    Returns:
        Un dictionnaire contenant les filtres à appliquer
    """

    filtre = options.get_filtre()
    return filtre

def filtre_ipOnly_EstActive() : 
    """
    Vérifie si le filtre "ip_only" est actif. Et vérifie si le filtre est au bon format (un str spécifique).
    Returns:
        True si le filtre "ip_only" est actif et au bon format, False sinon.
    """
    
    if "proto_filtre" in filtre_Selectionner().keys() and filtre_Selectionner()["proto_filtre"] == "ip_only" :
        return True
    return False

def filtre_arpOnly_EstActive() :
    """
    Vérifie si le filtre "arp_only" est actif. Et vérifie si le filtre est au bon format(un str spécifique).
    Returns:
        True si le filtre "arp_only" est actif et au bon format, False sinon.
    """
    
    if "proto_filtre" in filtre_Selectionner().keys() and filtre_Selectionner()["proto_filtre"] == "arp_only" :
        return True
    return False

def filtre_ipSpecifique_EstActive() :
    """
    Vérifie si le filtre "ip_specifique" est actif. Et vérifie si le filtre est au bon format (une adresse ip, ex : 192.168.1.1).
    Returns:
        True si le filtre "ip_specifique" est actif et au bon format, False sinon.
    """

    if "ip_specifique" in filtre_Selectionner().keys() and filtre_Selectionner()["ip_specifique"] is not None :
        filtre = filtre_Selectionner()["ip_specifique"]
        estUneip = True
        try:
            #Si on ne peut pas utiliser ip_address, c'est que le filtre n'est pas une adresse IP
            ipaddress.ip_address(filtre)

        except ValueError:

            estUneip = False

        if filtre is not None and estUneip: #Vérifie que le filtre ressemble à une adresse IP
            return True
        return False
    else : 
        return False

def filtre_portSpecifique_EstActive() :
    """" 
    Vérifie si le filtre "port_specifique" est actif. Et vérifie si le filtre est au bon format (un port, un entier entre 0 et 65535).
    Returns:
        True si le filtre "port_specifique" est actif et au bon format, False sinon.
    """

    if "port_specifique" in filtre_Selectionner().keys() and filtre_Selectionner()["port_specifique"] is not None :
        filtre = filtre_Selectionner()["port_specifique"]
    else :
        return False
    estUnPort = True
    if filtre is None :
        return False
    try:
        #Si on ne peut pas convertir le filtre en int, ce n'est pas un port
        filtre = int(filtre)

    except ValueError:

        estUnPort = False

    if estUnPort: #Vérifie que le filtre ressemble à un port
        if filtre >= 0 and filtre <= 65535 : #Vérifie que le port est dans la plage valide
            return True
    return False



def filtre_protocoleSpecifique_EstActive() :
    """
    Vérifie si le filtre "protocole_specifique" est actif. Et vérifie si le filtre est au bon format (un protocole valide 
    parmis la liste ['TCP', 'UDP', 'SCTP', 'ICMP', 'ICMPv6']).
    Returns:
        True si le filtre "protocole_specifique" est actif et au bon format, False sinon.
    """

    if "protocole_specifique" in filtre_Selectionner().keys() and filtre_Selectionner()["protocole_specifique"] is not None :
        filtre = filtre_Selectionner()["protocole_specifique"]
        protocoles_ip = ['TCP', 'UDP', 'SCTP', 'ICMP', 'ICMPv6']
        if filtre in protocoles_ip :
            return True
    return False

def liste_filtre_EstActive() :
    """
    Récupère la liste des filtres actifs et leurs valeurs.
    Donc si un filtre est vide ou invalide, le dictionnaire contiendra None ou false à l'emplacement de la valeur du filtre.
    Mais si un filtre est non vide et valide, alors le dictionnaire contiendra la valeur du filtre
    Returns:
        Un dictionnaire contenant les filtres actifs et leurs valeurs.
    """

    filtres = {}
    if filtre_ipOnly_EstActive() :
        filtres["ip_only"] = True
    else : 
        filtres["ip_only"] = False

    if filtre_arpOnly_EstActive() :
        filtres["arp_only"] = True
    else :
        filtres["arp_only"] = False

    if filtre_ipSpecifique_EstActive() :
        filtres["ip_specifique"] = filtre_Selectionner()["ip_specifique"]
    else :
        filtres["ip_specifique"] = None

    if filtre_portSpecifique_EstActive() :
        filtres["port_specifique"] = int(filtre_Selectionner()["port_specifique"])
    else :
        filtres["port_specifique"] = None

    if filtre_protocoleSpecifique_EstActive() :
        filtres["protocole_specifique"] = filtre_Selectionner()["protocole_specifique"]
    else :
        filtres["protocole_specifique"] = None
        
    return filtres