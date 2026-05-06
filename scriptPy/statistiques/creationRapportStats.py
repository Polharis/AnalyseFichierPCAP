def statsCoucheDeux(dicoReseau):
    """
    Calcule les statistiques des EtherTypes rencontrés dans les
    paquets analysés et les convertit en pourcentages.

    Compte le nombre de paquets par EtherType, puis calcule
    le pourcentage de chacun par rapport au total des paquets.

    Args:
        dicoReseau (dict): Dictionnaire contenant toutes les
                           informations extraites du fichier PCAP,
                           avec les EtherTypes comme clés.

    Returns:
        dict: Dictionnaire contenant :
            - total_paquet (int) : nombre total de paquets analysés
            - <EtherType> (float) : pourcentage de chaque EtherType
                                    sur le total des paquets

    Raises:
        ZeroDivisionError: Si dicoReseau est vide (total_paquet = 0).
    """
    #On compte le nombre de paquets de chaque type de protocole de couche 2
    stats = {}
    for protocols_couches_1 in dicoReseau.keys() : 
        stats[protocols_couches_1] = len(dicoReseau[protocols_couches_1])
    stats_pourcentage = {}
    total_paquet = 0
    for listes_paquets in dicoReseau.values() :
        total_paquet += len(listes_paquets)
    stats_pourcentage["total_paquet"] = total_paquet
    for protos in stats.keys() :
        stats_pourcentage[protos] = (stats[protos] / total_paquet) * 100

    return stats_pourcentage

def statsCoucheTrois(dicoReseau) :
    """
    Calcule les statistiques des protocoles de couche 3 rencontrés
    dans les paquets analysés et les convertit en pourcentages.

    Parcourt tous les paquets du dictionnaire et compte les occurrences
    de chaque protocole de couche 3, puis calcule le pourcentage
    de chacun par rapport au total des paquets.

    Args:
        dicoReseau (dict): Dictionnaire contenant toutes les
                           informations extraites du fichier PCAP,
                           avec les EtherTypes comme clés.

    Returns:
        dict: Dictionnaire contenant :
            - total_paquet (int) : nombre total de paquets analysés
            - <protocole_3> (float) : pourcentage de chaque protocole
                                      de couche 3 sur le total des paquets

    Raises:
        ZeroDivisionError: Si dicoReseau est vide (total_paquet = 0).
    """
    #On compte le nombre de paquets de chaque type de protocole de couche 3
    stats = {}
    for protocols_couches_1 in dicoReseau.keys() : 
        for paquet in dicoReseau[protocols_couches_1] :
            if 'protocole_3' in paquet.keys() :
                proto_couche_3 = paquet['protocole_3']
                if proto_couche_3 not in stats.keys() :
                    stats[proto_couche_3] = 1
                else :
                    stats[proto_couche_3] += 1
            else :
                if "PasDeProto" not in stats.keys() :
                    stats["PasDeProto"] = 1
                else : 
                    stats["PasDeProto"] += 1
    stats_pourcentage = {}
    total_paquet = 0
    for listes_paquets in dicoReseau.values() :
        total_paquet += len(listes_paquets)
    stats_pourcentage["total_paquet"] = total_paquet
    for protos in stats.keys() :
        stats_pourcentage[protos] = (stats[protos] / total_paquet) * 100

    return stats_pourcentage

def statsCoucheQuatre(dicoReseau) :
    """
    Calcule les statistiques des protocoles de couche 4 rencontrés
    dans les paquets analysés et les convertit en pourcentages.

    Parcourt tous les paquets du dictionnaire et compte les occurrences
    de chaque protocole de couche 4, puis calcule le pourcentage
    de chacun par rapport au total des paquets.

    Args:
        dicoReseau (dict): Dictionnaire contenant toutes les
                           informations extraites du fichier PCAP,
                           avec les EtherTypes comme clés.

    Returns:
        dict: Dictionnaire contenant :
            - total_paquet (int) : nombre total de paquets analysés
            - <protocole_4> (float) : pourcentage de chaque protocole
                                      de couche 4 sur le total des paquets

    Raises:
        ZeroDivisionError: Si dicoReseau est vide (total_paquet = 0).
    """
    #On compte le nombre de paquets de chaque type de protocole de couche 3
    stats = {}
    for protocols_couches_1 in dicoReseau.keys() : 
        for paquet in dicoReseau[protocols_couches_1] :
            if 'protocole_4' in paquet.keys() :
                proto_couche_4 = paquet['protocole_4']
                if proto_couche_4 not in stats.keys() :
                    stats[proto_couche_4] = 1
                else :
                    stats[proto_couche_4] += 1
            else :
                if "PasDeProto" not in stats.keys() :
                    stats["PasDeProto"] = 1
                else : 
                    stats["PasDeProto"] += 1

    stats_pourcentage = {}
    total_paquet = 0
    for listes_paquets in dicoReseau.values() :
        total_paquet += len(listes_paquets)
    stats_pourcentage["total_paquet"] = total_paquet
    for protos in stats.keys() :
        stats_pourcentage[protos] = (stats[protos] / total_paquet) * 100

    return stats_pourcentage

def statsCoucheServiceSource(dicoReseau) :
    """
    Calcule les statistiques des services source rencontrés
    dans les paquets analysés et les convertit en pourcentages.

    Parcourt tous les paquets du dictionnaire et compte les occurrences
    de chaque port source, puis calcule le pourcentage de chacun
    par rapport au total des paquets.

    Args:
        dicoReseau (dict): Dictionnaire contenant toutes les
                           informations extraites du fichier PCAP,
                           avec les EtherTypes comme clés.

    Returns:
        dict: Dictionnaire contenant :
            - total_paquet (int) : nombre total de paquets analysés
            - <port_src> (float) : pourcentage de chaque service
                                   source sur le total des paquets

    Raises:
        ZeroDivisionError: Si dicoReseau est vide (total_paquet = 0).
    """

    stats = {}
    for protocols_couches_1 in dicoReseau.keys() : 
        for paquet in dicoReseau[protocols_couches_1] :
            if 'port_src' in paquet.keys() :
                service = paquet['port_src']
                if service not in stats.keys() :
                    stats[service] = 1
                else :
                    stats[service] += 1
            else :
                if "PasDePort" not in stats.keys() :
                    stats["PasDePort"] = 1
                else : 
                    stats["PasDePort"] += 1

    stats_pourcentage = {}
    total_paquet = 0
    for listes_paquets in dicoReseau.values() :
        total_paquet += len(listes_paquets)
    stats_pourcentage["total_paquet"] = total_paquet
    for protos in stats.keys() :
        stats_pourcentage[protos] = (stats[protos] / total_paquet) * 100
    return stats_pourcentage    

def statsCoucheServiceDestination(dicoReseau) :
    """
    Calcule les statistiques des services destination rencontrés
    dans les paquets analysés et les convertit en pourcentages.

    Parcourt tous les paquets du dictionnaire et compte les occurrences
    de chaque port destination, puis calcule le pourcentage de chacun
    par rapport au total des paquets.

    Args:
        dicoReseau (dict): Dictionnaire contenant toutes les
                           informations extraites du fichier PCAP,
                           avec les EtherTypes comme clés.

    Returns:
        dict: Dictionnaire contenant :
            - total_paquet (int) : nombre total de paquets analysés
            - <port_dst> (float) : pourcentage de chaque service
                                   destination sur le total des paquets

    Raises:
        ZeroDivisionError: Si dicoReseau est vide (total_paquet = 0).
    """

    stats = {}
    for protocols_couches_1 in dicoReseau.keys() : 
        for paquet in dicoReseau[protocols_couches_1] :
            if 'port_dst' in paquet.keys() :
                service = paquet['port_dst']
                if service not in stats.keys() :
                    stats[service] = 1
                else :
                    stats[service] += 1
            else :
                if "PasDePort" not in stats.keys() :
                    stats["PasDePort"] = 1
                else : 
                    stats["PasDePort"] += 1
                    
    stats_pourcentage = {}
    total_paquet = 0
    for listes_paquets in dicoReseau.values() :
        total_paquet += len(listes_paquets)
    stats_pourcentage["total_paquet"] = total_paquet
    for protos in stats.keys() :
        stats_pourcentage[protos] = (stats[protos] / total_paquet) * 100
    return stats_pourcentage    

def liste_différence_src_dst_adjacente(dicoReseau,plage_temps_graphique) :
    """
    Crée un dictionnaire répertoriant les couples src-dst avec les
    différences de temps entre leurs paquets adjacents pairs.

    Pour chaque couple src-dst, les timestamps sont triés puis les
    différences de temps entre paquets adjacents pairs (i et i+1)
    sont calculées en millisecondes et arrondies au multiple de
    plage_temps_graphique le plus proche.
    Ce dictionnaire est utilisé pour générer les graphiques
    d'intra-espacement.
    
    Note : 
        Ce dictionnaire représente les intra espacement
        (temps entre deux paquets du même flot)

    Args:
        dicoReseau (dict): Dictionnaire contenant toutes les
                           informations extraites du fichier PCAP,
                           avec les EtherTypes comme clés.
        plage_temps_graphique (int): Intervalle de regroupement en
                                     millisecondes pour l'arrondi des
                                     différences de temps entre paquets.

    Returns:
        dict: Dictionnaire dont les clés sont des tuples (src, dst)
              et les valeurs des listes de différences de temps
              en millisecondes, arrondies à plage_temps_graphique.

    Raises:
        ZeroDivisionError: Si plage_temps_graphique est égal à zéro.
        KeyError: Si les clés "source" ou "destination" sont absentes
                  des paquets.
    """
    src_dst = {}
    src_dst_diff = {}
    for key in dicoReseau.keys() :
        for paquet in dicoReseau[key] :
            if "source" in paquet.keys() and "destination" in paquet.keys() :
                src_dst.setdefault((paquet["source"],paquet["destination"]),[]).append(paquet["time"])
    for couple in src_dst.keys() :
        liste_difference = []
        src_dst[couple].sort()
        for i in range (len(src_dst[couple])) :
            if i == len(src_dst[couple]) -1 :
                break

            n = src_dst[couple][i].timestamp() * 1000 #en millisecondes
            n_plus_un = src_dst[couple][i+1].timestamp() * 1000 #en millisecondes
            diff = n_plus_un - n
            # Arrondir au multiple de plage_temps_graphique le plus proche
            diff_arrondi = round(diff / plage_temps_graphique) * plage_temps_graphique
            liste_difference.append(diff_arrondi)
        src_dst_diff.setdefault(couple,liste_difference)

    return src_dst_diff

def creationRapport(mode,table) :
    """
    Génère un rapport textuel des statistiques du dictionnaire
    de paquets selon le mode sélectionné.

    Appelle la fonction de statistiques correspondant au mode,
    puis formate les résultats en une chaîne lisible indiquant
    le nombre total de paquets et le pourcentage de chaque
    protocole ou service.

    Note:
        Le mode "TempsVoyageMoyen" est disponible mais non
        recommandé pour le moment. Il est conservé pour de
        futures analyses plus poussées.

    Args:
        mode (str): Mode du rapport à générer. Valeurs acceptées :

                        - "CoucheDeux" : statistiques des EtherTypes
                        - "CoucheTrois" : statistiques des protocoles
                                          de couche 3
                        - "CoucheQuatre" : statistiques des protocoles
                                           de couche 4
                        - "CoucheServiceSource" : statistiques des
                                                  services source
                        - "CoucheServiceDestination" : statistiques des
                                                       services destination
                        - "TempsVoyageMoyen" : temps moyen aller-retour
                                               (non recommandé)
        table (dict): Dictionnaire contenant toutes les informations
                      extraites du fichier PCAP.

    Returns:
        str: Rapport textuel résumant les statistiques du mode
             sélectionné, ou chaîne vide si le mode est inconnu.

    Raises:
        KeyError: Si table ne contient pas les clés attendues
                  par la fonction de statistiques appelée.
    """

    rapport = ""
    if mode == "CoucheDeux" : 
        rapport += "Statistque sur la deuxième couche\n"
        stats = statsCoucheDeux(table)
        for stat in stats.keys() : 
            if stat == "total_paquet" :
                rapport += "Nombre total de paquets traités : " + str(stats[stat]) + "\n"
            else :
                rapport += " protocols : " + stat + " présents à " + str(stats[stat]) + "%\n"
    if mode == "CoucheTrois" :
        rapport += "Statistque sur la troisième couche\n"
        stats = statsCoucheTrois(table)
        for stat in stats.keys() : 
            if stat == "total_paquet" :
                rapport += "Nombre total de paquets traités : " + str(stats[stat]) + "\n"
            else :
                rapport += " protocols : " + stat + " présents à " + str(stats[stat]) + " %\n"
    if mode == "CoucheQuatre" :
        rapport += "Statistque sur la quatrième couche\n"
        stats = statsCoucheQuatre(table)
        for stat in stats.keys() : 
            if stat == "total_paquet" :
                rapport += "Nombre total de paquets traités : " + str(stats[stat]) + "\n"
            else :
                rapport += " protocols : " + stat + " présents à " + str(stats[stat]) + " %\n"
    if mode == "CoucheServiceSource" :
        rapport += "Statistque sur les services sources\n"
        stats = statsCoucheServiceSource(table)
        for stat in stats.keys() : 
            if stat == "total_paquet" :
                rapport += "Nombre total de paquets traités : " + str(stats[stat]) + "\n"
            else :
                rapport += " service : " + stat + " présents à " + str(stats[stat]) + " %\n"
    if mode == "CoucheServiceDestination" :
        rapport += "Statistque sur les services destinations\n"
        stats = statsCoucheServiceDestination(table)
        for stat in stats.keys() : 
            if stat == "total_paquet" :
                rapport += "Nombre total de paquets traités : " + str(stats[stat]) + "\n"
            else :
                rapport += " service : " + stat + " présents à " + str(stats[stat]) + " %\n"

    # Ce mode n'est pas pertinant, a ne pas  utiliser pour le moment, mais je le laisse au cas où je voudrais faire des analyses plus poussées sur les temps de voyage des paquets
    if mode == "TempsVoyageMoyen" :
        rapport += "Statistque sur le temps de voyage des paquets\n"
        stats = statsTempsVoyageMoyen(table)
        tars_moyens = stats[0]
        nb_tars = stats[1]
        if not tars_moyens :
            rapport += "Aucune paire de paquets aller-retour n'a été trouvée pour calculer les temps de voyage moyens.\n"
        else : 
            for conversation in tars_moyens.keys() :
                
                rapport += (
                    "Conversation entre " + conversation[0] + " et " + conversation[1] +
                    " : TAR moyen de " + str(tars_moyens[conversation]) + " secondes, basé sur " +
                    str(nb_tars[conversation]) + " paires aller-retour\n"
                )

    return rapport








#----------------------------------------------------------------------------------------------------
# ----------------------- A mettre entre parenthèse car je n'ai pas tout les outils -----------------


#Liste des temps de voyage pour chaque conversation (src, dst) 
# pour de futures analyses plus poussées sur les temps de voyage (ex : distribution des temps de voyage, etc...)
def dicoTempsParConversation(dicoReseau) :
    # Collecte des temps par conversation (src, dst)
    conversations = {}  # clé: (src, dst), valeur: liste des temps
    for protocoles_couches_1 in dicoReseau.keys() : 
        for paquet in dicoReseau[protocoles_couches_1] : 
            if "source" in paquet.keys() and "destination" in paquet.keys() : 
                key = (paquet["source"], paquet["destination"])
                # setDefault très pratique car évite de devoir vérifier si la clé existe déjà ou pas
                conversations.setdefault(key, []).append(paquet["time"])
    return conversations

#fait la moyenne du temps mis par chaque packet pout voyager entre la source et la destination
#Permet aussi d'obtenir le nombre de paires aller-retour pour chaque conversation (src, dst) 
# pour pouvoir faire des statistiques plus précises sur les temps de voyage moyens

def statsTempsVoyageMoyen(dicoReseau) :

    #Liste des conversations (src, dst) avec les temps de chaque paquet pour chaque conversation
    conversations = dicoTempsParConversation(dicoReseau)

    # Calcule des TAR (temps aller retour)moyens pour chaque paire
    tars_moyens = {}
    nb_tars = {}
    for (src, dst), times_out in conversations.items():
        #On récupère le temps du couple inverse (dst, src) pour trouver les temps de retour
        times_back = conversations.get((dst, src), [])
        if times_back:
            # Trie les temps
            times_out.sort()
            times_back.sort()
            # Calcule les différences pour les paires (aller-retour)
            num_pairs = min(len(times_out), len(times_back))
            diffs = []
            for i in range(num_pairs):
                diff = times_back[i] - times_out[i]
                if diff.total_seconds() > 0:
                    diffs.append(diff.total_seconds())
                    nb_tars[(src, dst)] = i +1
            if diffs:
                avg_rtt = sum(diffs) / len(diffs)
                tars_moyens[(src, dst)] = avg_rtt
                

    return [tars_moyens,nb_tars,conversations]

def statsTempsVoyageUnitaire(dicoReseau) : 

    #Liste des conversations (src, dst) avec les temps de chaque paquet pour chaque conversation
    conversations = dicoTempsParConversation(dicoReseau)

    tars_unitaires = {}
    for (src, dst), times_out in conversations.items():
        #On récupère le temps du couple inverse (dst, src) pour trouver les temps de retour
        times_back = conversations.get((dst, src), [])
        if times_back:
            # Trie les temps
            times_out.sort()
            times_back.sort()
            # Calcule les différences pour les paires (aller-retour)
            num_pairs = min(len(times_out), len(times_back))
            for i in range(num_pairs):
                diff = times_back[i] - times_out[i]
                if diff.total_seconds() > 0:
                    tars_unitaires.setdefault((src,dst),[]).append(diff.total_seconds())

    return tars_unitaires


