import sys
import os

# Remonte d'un niveau pour atteindre la racine du projet
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import dpkt
from scapy.all import *
from LectureDonne import trieDeDonnees as trieDeDonnees
from LectureDonne import optionsArgParse as optionsArgParse
from filtrageDonnee import listeFiltre as filtre  

cache = {'table': None, 'plage_temps': None,'filtres': None,'emplacement_fichier': None, "plage_temps_graph": None,'initialized': False}

def lancer_lecture_donne_fichier_unique():
   
    """
    Lance le parsing d'un fichier PCAP à l'aide de DPKT. 
    Applique aussi les différents filtres de l'application. 
    Utilise un cache pour garder en mémoire le parsing de PCAP si aucun paramètre n'as été modifier
    Note:
        Les paramètres sont récupérés automatiquement via optionsArgParse :
        - emplacement_fichier : chemin vers le fichier PCAP
        - plage_temps : plage de temps à analyser
        - plage_temps_graphique : plage de temps pour les graphiques
        - filtres_actives : liste des filtres activés
    Returns :
        le dictionnaire crée à l'issue du parsing du fichier PCAP
        Ainsi que la plage de temps séléctionner en paramètre
    Raises:
        FileNotFoundError: Si le fichier PCAP n'existe pas.
        Exception: Si le fichier n'est pas un format PCAP/PCAPng valide.
    """

    #Récupération de la plage de temps entrée en paramètre par l'utilisateur
    
    filtres_actives = filtre.liste_filtre_EstActive()

    plage_temps_graphique = optionsArgParse.get_plage_temps_graphique()

    #Récupération de l'emplacement du fichier si il y en a un
    emplacement_fichier = optionsArgParse.get_emplacement_fichier()

    #Vérification si les données ont déjà été traitées pour éviter de les retraiter à chaque fois
    if cache['initialized'] and cache['emplacement_fichier'] == emplacement_fichier and cache['filtres'] == filtres_actives and cache['plage_temps_graph'] == plage_temps_graphique:
        print("pas de chargement")
        return cache['table']

    # Récupération du fichier pcapng ou pcap
    with open(emplacement_fichier, 'rb') as f:
        magic = f.read(4)
        f.seek(0)  # rewind

        # Détection automatique du format
        if magic == b'\x0a\x0d\x0d\x0a':
            reader = dpkt.pcapng.Reader(f)
        else:
            reader = dpkt.pcap.Reader(f)

        #Table contenant tous les paquets
        table_par_protocole = {}
        i = 0

        for ts, buf in reader:
            if i % 1000 == 0:  
                print("chargement " + str(i) + " paquets lus")
            
            # Vérifier que c'est bien une couche Ethernet valide
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth, dpkt.ethernet.Ethernet):
                    ip = eth.data
                    #print(datetime.datetime.fromtimestamp(float(ts)))
                    #print(type(eth.data))
                    table_par_protocole = trieDeDonnees.ajouter_a_table_Par_Protocole(table_par_protocole, eth, i + 1, filtres_actives,ts)
            except:
                # Ignorer les paquets qui ne peuvent pas être parsés
            
                pass
            
            i += 1

    cache['table'] = table_par_protocole
    cache['initialized'] = True
    cache['filtres'] = filtres_actives
    cache['emplacement_fichier'] = emplacement_fichier
    cache['plage_temps_graph'] = plage_temps_graphique
    return table_par_protocole

#Actuelement, ne sert à rien car il à été décidé de retirer plage_temps du code
#Mais trop de fonction lui font appel, pour qu'elle soit supprimer 
def get_table_par_protocole() :
    
    infos_PCAP = lancer_lecture_donne_fichier_unique()
    
    return infos_PCAP

#Print de test
#print(tableParProtocole.values())








