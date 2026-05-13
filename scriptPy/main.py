from LectureDonne import optionsArgParse as options
from scapy.all import *
import  LectureDonne.lectureDonneFichierUnique as recupDico  
import LectureDonne.creationCSV as creationCSV
import statistiques.creationRapportStats as stats
import graphiques.creationGraphiques as graphiques
import LectureDonne.detectionAnomalie as anomalie





#Cette fonctions doit être postionner ici et non pas dans app
#Cela est dû au principe identification de module par chemin d'import de python
def configurerParams (params) : 
    options.appliquer_filtres(params)

def genererGraphique(TypeGraphique,plage_temps_graphique) :

    """
    Génère un graphique en fonction du type et de la plage de temps spécifiés.
    Args:
        TypeGraphique (str): Le type de graphique à générer (ex: "CoucheDeux", "CoucheTrois", "CoucheQuatre", "CoucheServiceSource", "CoucheServiceDestination", "IntraEspacement", "IntraEspacementRepartition").
        plage_temps_graphique (tuple): La plage de temps pour laquelle générer le graphique (ex: (start_time, end_time)).
    Returns:
        Un graphique généré en fonction du type et de la plage de temps spécifiés.
    """
    table_par_protocole = recupDico.get_table_par_protocole()
    
    if TypeGraphique == "CoucheDeux" :
        return graphiques.statistiqueSousgraphique(stats.statsCoucheDeux(table_par_protocole),"EtherType")
    elif TypeGraphique == "CoucheTrois" :
        return graphiques.statistiqueSousgraphique(stats.statsCoucheTrois(table_par_protocole),"CoucheTrois")
    elif TypeGraphique == "CoucheQuatre" :
        return graphiques.statistiqueSousgraphique(stats.statsCoucheQuatre(table_par_protocole),"CoucheQuatre")
    elif TypeGraphique == "CoucheServiceSource" :
        return graphiques.statistiqueSousgraphique(stats.statsCoucheServiceSource(table_par_protocole),"CoucheServiceSource")
    elif TypeGraphique == "CoucheServiceDestination" :
         return graphiques.statistiqueSousgraphique(stats.statsCoucheServiceDestination(table_par_protocole),"CoucheServiceDestination")
    elif TypeGraphique == "IntraEspacement" :
        return graphiques.histogrammeIntraEspacement(stats.liste_différence_src_dst_adjacente(table_par_protocole,plage_temps_graphique),plage_temps_graphique)
    elif TypeGraphique == "IntraEspacementRepartition" :
        return graphiques.courbeRepartitionIntraInterEspacement(stats.liste_différence_src_dst_adjacente(table_par_protocole,plage_temps_graphique),plage_temps_graphique,"intra")
    elif TypeGraphique == "InterEspacementRepartition" :
        return graphiques.courbeRepartitionIntraInterEspacement(stats.liste_différence_src_dst_inter(table_par_protocole,plage_temps_graphique),plage_temps_graphique,"inter")
    else :
        return None

def genererRapportCsv() :
    """
    Génère un rapport CSV contenant toutes les informations extraites du fichier PCAP.
    Returns:
        Un rapport CSV généré avec toutes les informations extraites du fichier PCAP.
    """
    table_par_protocole = recupDico.get_table_par_protocole()
    creationCSV.creationCSVtoutesInfos(table_par_protocole)

def genererRapportStatistique(mode) :
    """
    Génère un rapport statistique en fonction du mode spécifié.
    Args:
        mode (str): Le mode pour lequel générer le rapport statistique (ex: "CoucheDeux", "CoucheTrois", "CoucheServiceSource", "CoucheServiceDestination").
    Returns:
        Un rapport statistique généré en fonction du mode spécifié.
    """

    table_par_protocole = recupDico.get_table_par_protocole()
    if mode == "CoucheDeux" :
        return stats.creationRapport(mode,table_par_protocole)
    elif mode == "CoucheTrois" :
        return stats.creationRapport(mode,table_par_protocole)
    elif mode == "CoucheServiceSource" :    
        return stats.creationRapport(mode,table_par_protocole)
    elif mode == "CoucheServiceDestination" :
        return stats.creationRapport(mode,table_par_protocole)
    elif mode == "flux" :
        return stats.creationRapport(mode, table_par_protocole)
    elif mode == "nbPaquet" :
        print(identifierLesAnomalies())
        return stats.creationRapport(mode, table_par_protocole)
    elif mode == "ipPlusActiveSrc" :
        return stats.creationRapport(mode, table_par_protocole)
    elif mode == "ipPlusActiveDst" :
        return stats.creationRapport(mode, table_par_protocole)
    else :
        return None

def identifierLesAnomalies() : 
    table_par_protocole = recupDico.get_table_par_protocole()

    return anomalie.detectionScanDePort(table_par_protocole)

#liste chemin du fichier PCAP à analyser
#/home/stagetesa/Downloads/NMAP_PROBE.pcap