import os

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
   
    
def get_filtre():
    """
    Accesseur pour le dictionnaire global filtres_à_appliquer.

    Permet aux fonctions extérieures à ce fichier d'accéder
    aux filtres actifs sans modifier directement la variable globale.

    Returns:
        dict: Dictionnaire des filtres actifs et leurs valeurs.

    Raises:
        NameError: Si filtres_à_appliquer n'a pas été initialisé.
    """
    args = filtres_à_appliquer
    
    return args

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




