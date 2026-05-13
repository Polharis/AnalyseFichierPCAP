def detectionScanDePort(table):
    rapport_anomalie = ""
    nb_requete_par_ip = {}
    ip_anormales = []
    

    for cle in table.keys() :

        for paquet in table[cle] :
            if "flag" in paquet.keys() :
                seconde = (int(paquet["time"].timestamp()) // 1) * 1
                for key in list(nb_requete_par_ip.keys()):
                    
                    if (paquet["source"],seconde) == key and \
                        paquet["port_dst"] not in nb_requete_par_ip[key][1] and paquet["flag"] == ['SYN']: 
                        nb_requete_par_ip[(paquet["source"],seconde)][0] += 1
                        nb_requete_par_ip[(paquet["source"],seconde)][1].append(paquet["port_dst"])

                if (paquet["source"],seconde) not in nb_requete_par_ip : 
                    nb_requete_par_ip[(paquet["source"],seconde)] = [1,[paquet["port_dst"]]]

    print (nb_requete_par_ip)
    for key in nb_requete_par_ip.keys() :
        if nb_requete_par_ip[key][0] > 10 :
            if key[0] not in ip_anormales :
                ip_anormales.append(key[0])
                print(key[1])

    if len(ip_anormales) == 0 :
        rapport_anomalie = "aucune anomalie"
    else : 
        for ip in ip_anormales :
            rapport_anomalie = rapport_anomalie + "Il y a une anomalie avec l'ip " + ip + " \n"

    return rapport_anomalie