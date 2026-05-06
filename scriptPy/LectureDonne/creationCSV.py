from scapy.all import *
import csv


#Récupération du dictionnaire contenant les données extraites du fichier pcapng
def creationCSVtoutesInfos(table_par_protocole):
    """
    Exporte toutes les informations extraites d'un fichier PCAP dans un fichier CSV.

    Construit une liste de listes à partir du dictionnaire contenant
    toutes les informations du fichier PCAP, puis l'écrit dans
    scriptPy/DataOutput/data.csv.

    Args:
        table_par_protocole (dict): Dictionnaire des paquets extraits
                                    du fichier PCAP.

    Returns:
        None

    Raises:
        FileNotFoundError: Si le dossier DataOutput n'existe pas.
        PermissionError: Si l'écriture dans le dossier est refusée.
    
    """


    #Création du fichier csv avec les données extraites du fichier pcapng

    #Informations de la première colonne du CSV
    premiereColonne = []
    for donnee in table_par_protocole.values() :
        for dico in donnee : 
            for info in dico.keys() :
                if info not in premiereColonne :
                    premiereColonne.append(info)

    #Toutes les informations
    toutesInfos = [['donnees']]
    i = 0
    for donnee in table_par_protocole.values() :
        for dico in donnee : 
                #On fait une simple numérotation des paquets traités
                i += 1
                toutesInfos[0].append(str(i))


    #On parcourt toutes les données de chaque catégorie 
    #Et on les met dans une même colonne
    #Ainsi on peut faire un CSV en choisissant "," comme séparateur
    for (i) in range (0, len(premiereColonne)) :
        toutesInfos.append([])
        toutesInfos[i+1].append(premiereColonne[i])
        #Parcours de toutes les données le même nombre de fois que de type d'information
        #Cela pourrait être optimisé
        for donnee in table_par_protocole.values() :
            for dico in donnee : 
                #Alors on met 'None' dans la case correspondante
                if premiereColonne[i] not in dico.keys() : 
                    toutesInfos[i+1].append("None")
                else :
                    #Sinon on ajoute la donnée trouvée
                    toutesInfos[i+1].append(dico[premiereColonne[i]])


    # Écrire le CSV
    with open('scriptPy/DataOutput/data.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        for lignes in toutesInfos :
            writer.writerow(lignes)
        
    f.close()

