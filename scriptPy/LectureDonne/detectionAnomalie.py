def detectionScanDePort(table):
    rapport_anomalie = ""
    nb_requete_par_ip = {}
    ip_anormales = set()  # set au lieu de list → recherche O(1)

    for cle in table:
        for paquet in table[cle]:

            if "flag" in paquet.keys() :
                print(paquet["flag"])
                
            if "flag" not in paquet or paquet["flag"] != ["SYN"]:
                continue  # on ignore directement les paquets non SYN

            
            seconde = int(paquet["time"].timestamp())
            cle_ip = (paquet["source"], seconde)
            port = paquet["port_dst"]

            if cle_ip not in nb_requete_par_ip:
                nb_requete_par_ip[cle_ip] = [1, {port}]  # set pour les ports
            elif port not in nb_requete_par_ip[cle_ip][1]:
                nb_requete_par_ip[cle_ip][0] += 1
                nb_requete_par_ip[cle_ip][1].add(port)

    
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