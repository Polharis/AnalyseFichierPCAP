import sys
import os

# Remonte d'un niveau pour atteindre la racine du projet
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from LectureDonne import optionsArgParse as options
import ipaddress

# Chemin par défaut relatif à la location de ce fichier
FICHIER_PCAP_DEFAUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "DataEntry",
    "exempleCaptureWireshark.pcapng"
)

filtres_à_appliquer = {}

def appliquer_filtres(params):

    """
    Stocke les filtres reçus depuis l'application web dans le
    dictionnaire global filtres_à_appliquer.

    Ce dictionnaire sera ensuite utilisé par les autres fonctions
    du fichier pour filtrer les paquets à analyser.

    Args:
        params (dict): Paramètres de filtrage reçus depuis
                       l'application web.

    Returns:
        None

    Raises:
        TypeError: Si params n'est pas un dictionnaire.
    """

    #Ici on applique les filtres en fonction des paramètres reçus
    for key, value in params.items():
        filtres_à_appliquer[key] = value





def filtre_Selectionner() :
    """
    Récupère les données des champs de filtres sélectionnés par l'utilisateur.
    Returns:
        Un dictionnaire contenant les filtres à appliquer
    """

    filtre = filtres_à_appliquer
    return filtre


def get_emplacement_fichier():
    """
    Récupère l'emplacement du fichier PCAP à analyser et en attribue
    un par défaut si le chemin est absent, incorrect ou ne correspond
    pas à un fichier PCAP ou PCAPng valide.

    Note:
        La validité du fichier est vérifiée par lecture des magic bytes :
        - PCAPng : 0x0a0d0d0a
        - PCAP    : 0xd4c3b2a1 ou 0xa1b2c3d4

    Returns:
        str: Chemin vers un fichier PCAP ou PCAPng valide,
             ou chemin par défaut si le fichier est invalide.

    Raises:
        FileNotFoundError: Si le fichier par défaut est introuvable.
    """
    if ("chemin_fichier" in filtres_à_appliquer.keys()
            and filtres_à_appliquer["chemin_fichier"] is not None
            and filtres_à_appliquer["chemin_fichier"] != ""):

        chemin = filtres_à_appliquer["chemin_fichier"]

        # Vérification que le fichier existe
        if not os.path.exists(chemin):
            print(f"Fichier introuvable : {chemin}, utilisation du fichier par défaut")
            return FICHIER_PCAP_DEFAUT

        # Vérification que c'est bien un fichier PCAP ou PCAPng par magic bytes
        try:
            with open(chemin, 'rb') as f:
                magic = f.read(4)
            MAGIC_PCAPNG  = b'\x0a\x0d\x0d\x0a'
            MAGIC_PCAP_LE = b'\xa1\xb2\xc3\xd4'  # little-endian
            MAGIC_PCAP_NS = b'\xa1\xb2\x3c\x4d'  # little-endian nanosecondes
            MAGIC_PCAP_BE = b'\xd4\xc3\xb2\xa1'  # big-endian
            MAGIC_PCAP_BE_NS = b'\x4d\x3c\xb2\xa1'  # big-endian nanosecondes

            if magic not in (MAGIC_PCAPNG, MAGIC_PCAP_LE, MAGIC_PCAP_NS, 
                            MAGIC_PCAP_BE, MAGIC_PCAP_BE_NS):
                print(f"Format invalide : {chemin}, utilisation du fichier par défaut")
                return FICHIER_PCAP_DEFAUT
        except (IOError, OSError):
            print(f"Impossible de lire : {chemin}, utilisation du fichier par défaut")
            return FICHIER_PCAP_DEFAUT

        return chemin

    return FICHIER_PCAP_DEFAUT


def get_plage_temps_graphique() :
    """
    Accesseur pour le paramètre de regroupement temporel utilisé
    dans les graphiques d'inter-intra espacement.

    Récupère la valeur depuis le dictionnaire global
    filtres_à_appliquer si elle est définie et non vide.

    Returns:
        float: Plage de temps en millisecondes à appliquer
               sur les graphiques.
        None: Si le paramètre est absent ou vide.

    Raises:
        TypeError: Si la valeur récupérée n'est pas convertible
                   en nombre.
    """
    if "plage_temps_graphique" in filtres_à_appliquer.keys() and filtres_à_appliquer["plage_temps_graphique"] is not None and filtres_à_appliquer["plage_temps_graphique"] != "" :
        return filtres_à_appliquer["plage_temps_graphique"]
    else :
        return None




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
    parmis la liste ['tcp', 'udp', 'sctp', 'icmp', 'icmpv6']).
    Returns:
        True si le filtre "protocole_specifique" est actif et au bon format, False sinon.
    """
    if "protocol_specifique" in filtre_Selectionner().keys() and filtre_Selectionner()["protocol_specifique"] is not None :
        filtre = filtre_Selectionner()["protocol_specifique"]
        protocoles_ip = ['tcp', 'udp', 'sctp', 'icmp', 'icmpv6']
        if filtre.lower() in protocoles_ip :
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
    if filtre_ipSpecifique_EstActive() :
        filtres["ip_specifique"] = filtre_Selectionner()["ip_specifique"]
    else :
        filtres["ip_specifique"] = None

    if filtre_portSpecifique_EstActive() :
        filtres["port_specifique"] = int(filtre_Selectionner()["port_specifique"])
    else :
        filtres["port_specifique"] = None

    if filtre_protocoleSpecifique_EstActive() :
        filtres["protocol_specifique"] = filtre_Selectionner()["protocol_specifique"]
    else :
        filtres["protocol_specifique"] = None

    filtres["emplacement_fichier"] = get_emplacement_fichier()
    filtres["palge_temps"] = get_plage_temps_graphique()
        
    return filtres