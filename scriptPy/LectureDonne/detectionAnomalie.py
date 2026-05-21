def detectionScanDePort(table):
    """
    Détecte les scans de ports probables dans un dictionnaire de paquets.
    Via une liste de critère précis,
    si une adresse IP source envoie plus de 10 paquets SYN à des ports différents dans la même seconde,
    alors on considère qu'il y a un scan de port probable avec cette adresse IP.
    De plus, on vérifie aussi si le paquet qui suit la requête SYN contient un flag RST 
    Args:
        table (dict): Dictionnaire des paquets extraits du fichier PCAP, organisé par protocole.
    Returns:
        Un rapport de détection d'anomalies, indiquant les adresses IP suspectes et les raisons de leur suspicion.
    Raises:
        ValueError: Si le format des données dans le dictionnaire n'est pas conforme aux attentes 
                    (par exemple, si les champs "time", "source", "port_dst" ou "flag" sont manquants ou mal formatés).
    """
    rapport_anomalie = ""
    nb_requete_par_ip = {}
    ip_anormales = set()  # set au lieu de list → recherche O(1)
    requete_SYN_precendent = False

    for cle in table:
        for paquet in table[cle]:

            if requete_SYN_precendent :
                if "flag" in paquet.keys() and "RST" in paquet["flag"]  :
                    requete_SYN_precendent = False
                    
                    if cle_ip not in nb_requete_par_ip:
                        nb_requete_par_ip[cle_ip] = [1, {port}]  # set pour les ports
                    elif port not in nb_requete_par_ip[cle_ip][1]:
                        nb_requete_par_ip[cle_ip][0] += 1
                        nb_requete_par_ip[cle_ip][1].add(port)

                    continue
                else : 
                    requete_SYN_precendent = False

            if "flag" not in paquet or paquet["flag"] != ["SYN"]:
                continue  # on ignore directement les paquets non SYN

            seconde = int(paquet["time"].timestamp())
            cle_ip = (paquet["source"], seconde)
            port = paquet["port_dst"]
            requete_SYN_precendent = True

            
    
    for (ip, _), (count, _) in nb_requete_par_ip.items():
        if count > 10:
            ip_anormales.add(ip)

    print("anomalie renconctré : " + str(ip_anormales))
    if len(ip_anormales) == 0 :
        rapport_anomalie = "aucune anomalie"
    else : 
        for ip in ip_anormales :
            rapport_anomalie = rapport_anomalie + "Il y a un scan de port probable avec l'ip " + ip + " \n"

    return rapport_anomalie