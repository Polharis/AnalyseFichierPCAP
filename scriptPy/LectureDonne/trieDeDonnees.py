from scapy.all import *
import datetime  
from datetime import timedelta  
import dpkt

#Cette fonction permet d'ajouter les informations d'un paquet ARP dans la liste PCAPARP



#Créer des couples clé-valeur : type de payload Ethernet, paquets associés

def ajouter_a_table_Par_Protocole(table, paquet,numero_paquet,filtres_actives,time):
    """
    Construit un dictionnaire de paquets en extrayant les informations
    du parsing PCAP et en appliquant les filtres actifs.

    Le premier rôle est d'appeler les fonctions chargées de construire
    le dictionnaire à partir des informations du parsing PCAP,
    difficilement exploitables en l'état.
    Le deuxième rôle est d'appliquer les filtres actifs lors de
    la construction du dictionnaire.

    Args:
        table (dict): Dictionnaire construit à partir des informations
                      du parsing du fichier PCAP.
        paquet (dpkt.ethernet.Ethernet): Résultat du parsing du fichier
                                         PCAP à l'aide de dpkt.
        numero_paquet (int): Numéro du paquet traité.
        filtres_actives (dict): Dictionnaire des filtres activés avec
                                leurs valeurs respectives.
        time (float): Timestamp du paquet.

    Returns:
        dict: Le dictionnaire mis à jour avec les informations du paquet,
              ou inchangé si le paquet ne répond pas aux filtres actifs.

    Raises:
        KeyError: Si un filtre attendu est absent de filtres_actives.
    """
    EtherType = type(paquet.data).__name__
    #Si le payload en question n'a jamais été trouvé alors on le crée
    if EtherType not in table:
        table[EtherType] = []
    #On ajoute un dictionnaire par paquet

    #--------------- FILTRES ---------------
    
    #Si l'option ip_specifique est activée, on n'ajoute que les paquets provenant ou étant déstiné à l'adresse IP spécifiée
    if filtres_actives["ip_specifique"] is not None:
        if EtherType != 'IP' and EtherType != 'ARP' :
            return table
        if EtherType == 'IP' :
            if socket.inet_ntoa(paquet.data.src) != filtres_actives["ip_specifique"] and socket.inet_ntoa(paquet.data.dst) != filtres_actives["ip_specifique"]:
                return table
        elif EtherType == 'ARP' :
            if  socket.inet_ntoa(paquet.data.spa) != filtres_actives["ip_specifique"] and socket.inet_ntoa(paquet.data.tpa) != filtres_actives["ip_specifique"]:
                return table
            
    #Si l'option port_specifique est activée, on n'ajoute que les paquets provenant ou étant déstiné au port spécifié
    if filtres_actives["port_specifique"] is not None:
        if EtherType != 'IP' :
            return table
        if not (isinstance(paquet.data.data, dpkt.tcp.TCP) or isinstance(paquet.data.data, dpkt.udp.UDP) or isinstance(paquet.data.data, dpkt.sctp.SCTP)) :
            return table
        if paquet.data.data.sport != filtres_actives["port_specifique"] and paquet.data.data.dport != filtres_actives["port_specifique"]:
            return table
        
    #Si l'option protocole_specifique est activée, on n'ajoute que les paquets de type IP avec le protocole de couche 4 spécifié
    if filtres_actives["protocol_specifique"] is not None:
        print(EtherType)
        if EtherType != 'IP' and EtherType != 'IPv6' :
            return table
        if EtherType == 'IP' :
            proto_name = get_proto_name(paquet.data.p)
            if proto_name.lower() != filtres_actives["protocol_specifique"].lower() :
                return table
        elif EtherType == 'IPv6' :
            proto_name = get_proto_name(paquet.data.nxt)
            if proto_name.lower() != filtres_actives["protocol_specifique"].lower() :
                return table
    #---------------- FIN DES FILTRES ---------------
   
    table[EtherType].append(extraire_info(paquet, numero_paquet,time))
    return table

dico_proto_deja_traites = {}
dico_services_deja_traites = {} 

#fonction pour l'optimisation du temps de traitement
#On évite de lire les fichiers tout le temps 
def deja_traite_proto(proto_num):
    """
    Optimise le traitement des paquets en mettant en cache les protocoles
    déjà identifiés pour éviter de relire /etc/protocols à chaque itération.

    Si le numéro de protocole est supérieur à 262, il est directement
    considéré comme inconnu sans lecture du fichier.

    Note:
        Sur un fichier PCAP de 20 Mo, cette optimisation réduit le temps
        de traitement de 3 minutes à 55 secondes.

    Args:
        proto_num (int): Numéro du protocole extrait du paquet.

    Returns:
        str: Le nom du protocole s'il est déjà en cache ou supérieur à 262
             (retourne "Unknown" dans ce dernier cas).
        None: Si le protocole doit être recherché dans /etc/protocols.

    Raises:
        TypeError: Si proto_num n'est pas un entier.
    """
    if proto_num in dico_proto_deja_traites.keys() :
        return dico_proto_deja_traites[proto_num]
    elif proto_num > 262 :
        #Pour éviter de faire des recherches dans le fichier /etc/protocols pour les numéros de protocoles qui sont très élevés et qui sont souvent inconnus, on considère que tous les numéros de protocoles supérieurs à 262 sont inconnus
        return "Unknown"
    else :
        return None
    
def deja_traite_service(port_num):
    """
    Optimise le traitement des paquets en mettant en cache les services
    déjà identifiés pour éviter de relire /etc/services à chaque itération.

    Si le numéro de service est supérieur à 65535, il est directement
    considéré comme inconnu sans lecture du fichier.

    Note:
        Sur un fichier PCAP de 20 Mo, cette optimisation réduit le temps
        de traitement de 3 minutes à 55 secondes.

    Args:
        port_num (int): Numéro du service extrait du paquet.

    Returns:
        str: Le nom du service s'il est déjà en cache ou supérieur à 65535
             (retourne "Unknown" dans ce dernier cas).
        None: Si le service doit être recherché dans /etc/services.

    Raises:
        TypeError: Si port_num n'est pas un entier.
    """
    if port_num in dico_services_deja_traites.keys() :
        return dico_services_deja_traites[port_num]
    elif port_num > 65535 :
        #Pour éviter de faire des recherches dans le fichier /etc/services pour les numéros de ports qui sont très élevés et qui sont souvent inconnus, on considère que tous les numéros de ports supérieurs à 65535 sont inconnus
        return "Unknown (souvent un port éphémère)"
    else :
        return None
    

#L'appel paquet.proto renvoie un int qui est lié à un protocole de la couche 4,
# cette fonction permet de faire le lien entre ce numéro et le nom du protocole
#Lire le fichier /etc/protocols pour faire le lien entre les numéros et les protocoles
def get_proto_name(proto_num):
    """
    Lit le fichier système des protocoles pour faire correspondre
    un numéro de protocole avec son nom.

    Note:
        - Fonctionne sur Linux (/etc/protocols) et Windows
          (C:\\Windows\\System32\\drivers\\etc\\protocol).
        - Fait appel à deja_traite_proto() pour éviter de relire
          le fichier à chaque appel.

    Args:
        proto_num (int): Numéro du protocole extrait du paquet.

    Returns:
        str: Le nom du protocole correspondant au numéro,
             ou "Unknown" si le protocole n'est pas répertorié.

    Raises:
        FileNotFoundError: Si aucun fichier de protocoles n'est trouvé.
        TypeError: Si proto_num n'est pas un entier.
    """
    
    est_deja_traite = deja_traite_proto(proto_num)
    if est_deja_traite is not None :
        return est_deja_traite
    path = "/etc/protocol"
    if os.path.exists("/etc/protocols") :
        path = "/etc/protocols"
    else :
        #Chemin alternatif si on est sur windows
        path = "/usr/share/protocol"
        
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ligne in f:
            ligne = ligne.split("#", 1)[0].strip()
            if not ligne:
                continue
            champs = ligne.split()
            if len(champs) < 2:
                continue
            try:
                if int(champs[1]) == proto_num:
                    dico_proto_deja_traites[proto_num] = champs[0]
                    return champs[0]
            except ValueError:
                continue
    dico_proto_deja_traites[proto_num] = "Unknown"
    return "Unknown"

def get_service_name(port_num):
    """
    Lit le fichier système des services pour faire correspondre
    un numéro de service avec son nom.

    Note:
        - Fonctionne sur Linux (/etc/protocols) et Windows
          (C:\\Windows\\System32\\drivers\\etc\\protocol).
        - Fait appel à deja_traite_service() pour éviter de relire
          le fichier à chaque appel.

    Args:
        port_num (int): Numéro du service extrait du paquet.

    Returns:
        str: Le nom du service correspondant au numéro,
             ou "Unknown" si le service n'est pas répertorié.

    Raises:
        FileNotFoundError: Si aucun fichier de protocoles n'est trouvé.
        TypeError: Si port_num n'est pas un entier.
    """
    est_deja_traite = deja_traite_service(port_num)
    if est_deja_traite is not None :
        return est_deja_traite
    with open("/etc/services", "r", encoding="utf-8", errors="ignore") as f:
        for ligne in f:
            ligne = ligne.split("#", 1)[0].strip()
            if not ligne:
                continue
            champs = ligne.split()
            if len(champs) < 2:
                continue
            name = champs[0]
            port_proto = champs[1]
            if '/' in port_proto:
                port_str, protocol = port_proto.split('/')
                try:
                    port = int(port_str)
                    if port == port_num :
                        dico_services_deja_traites[port_num] = name
                        return name
                except ValueError:
                    continue
    dico_services_deja_traites[port_num] = "Unknown (souvent un port éphémère)"
    return "Unknown (souvent un port éphémère)"


#L'appel paquet.ptype renvoie un int qui est lié à un protocole de la couche 3,
# cette fonction permet de faire le lien entre ce numéro et le nom du protocole
def get_arp_proto_name(arp_ptype_num):
    """
    Convertit un numéro de protocole de couche 3 issu d'un paquet ARP
    en son nom lisible, via un dictionnaire statique.

    Dans la couche ARP, les protocoles sont identifiés par des entiers
    spécifiques (EtherType), différents des numéros de protocoles
    classiques de couche 4.

    Args:
        arp_ptype_num (int): Numéro du protocole ARP (EtherType)
                             extrait du paquet.

    Returns:
        str: Le nom du protocole correspondant (IPv4, ARP, IPv6),
             ou "Unknown" si le numéro n'est pas répertorié.

    Raises:
        TypeError: Si arp_ptype_num n'est pas un entier.
    """
    arp_proto_map = {
        2048: 'IPv4',
        2054: 'ARP',
        34525: 'IPv6'
    }
    for key in arp_proto_map.keys() :
        if key == arp_ptype_num :
            return arp_proto_map[arp_ptype_num] 
    return 'Unknown'


def Est_protocole_couche_4(proto_num) :
    """
    Vérifie si un numéro de protocole de couche 3 correspond
    à un protocole de couche 4 (TCP, UDP, SCTP, DCCP).

    Cette vérification est importante pour déterminer si les
    numéros de ports source et destination peuvent être extraits
    du paquet.

    Args:
        proto_num (int): Numéro du protocole de couche 3
                         extrait du paquet.

    Returns:
        bool: True si le protocole est de couche 4
              (TCP, UDP, SCTP, DCCP), False sinon.

    Raises:
        TypeError: Si proto_num n'est pas un entier.
    """
    proto_couche_4 = ["tcp", "udp", "sctp","dccp"]
    proto_name = get_proto_name(proto_num)
    if proto_name in proto_couche_4 :
        return True
    else :
        return False

def extraire_info(paquet,num_paquet,time) : 
    """
    Fonction principale de construction d'un dictionnaire exploitable
    depuis un objet dpkt.ethernet.Ethernet.

    Utilise les outils dpkt pour transformer l'objet en informations
    lisibles (noms de couches, ports, adresses IP, etc.).
    Le contenu du dictionnaire retourné varie selon le type de paquet
    (IP, ARP, IPv6, ou payload non reconnu).

    Note:
        Fait appel à presque toutes les autres fonctions du fichier
        pour extraire les informations (get_proto_name,
        get_service_name, Est_protocole_couche_4, etc.).

    Args:
        paquet (dpkt.ethernet.Ethernet): Paquet duquel extraire
                                         les informations.
        num_paquet (int): Numéro du paquet traité.
        time (float): Timestamp Unix du paquet extrait par dpkt.

    Returns:
        dict: Dictionnaire contenant selon le type de paquet :
            - id, type_payload, time, mac_src, mac_dst
              (toujours présents)
            - source, destination (si IP, ARP ou IPv6)
            - protocole_3 ou protocole_4 (si protocole identifié)
            - ttl (si IP ou IPv6)
            - port_src, port_dst (si TCP, UDP ou SCTP)
            - ni IP ni ARP (bool) : True si payload non reconnu

    Raises:
        AttributeError: Si le paquet ne possède pas les attributs
                        attendus.
        socket.error: Si la conversion d'adresse IP échoue.
    """
    couche_trois = paquet.data
    transport = couche_trois.data
    #On ajoute d'abord les informations communes à tous les paquets
    Infos = {
        'id' : num_paquet,
        #Date sous format AAAA-MM-JJ HH:MM:SS millisecondes
        
        'type_payload': type(couche_trois).__name__,
        'time': datetime.datetime.fromtimestamp(float(time)),
        'mac_src': dpkt.ethernet.mac_to_str(paquet.src),
        'mac_dst': dpkt.ethernet.mac_to_str(paquet.dst)
    }

    #Dans cette section on va avoir des types d'informations différents selon le type de payload du paquet Ethernet
    #On vérifie que le layer ip existe
    if isinstance(paquet.data, dpkt.ip.IP):
        if Est_protocole_couche_4(couche_trois.p) :
            Infos['protocole_4'] = get_proto_name(couche_trois.p)
        else : 
            Infos['protocole_3'] = get_proto_name(couche_trois.p)
        Infos['ttl'] = couche_trois.ttl
        Infos['source'] = socket.inet_ntoa(couche_trois.src)
        Infos['destination'] = socket.inet_ntoa(couche_trois.dst)
        Infos['ni IP ni ARP'] = False
        if isinstance(couche_trois.data, (dpkt.tcp.TCP, dpkt.udp.UDP, dpkt.sctp.SCTP)):
            Infos['port_src'] = get_service_name(couche_trois.data.sport)
            Infos['port_dst'] = get_service_name(couche_trois.data.dport)
    elif isinstance(paquet.data, dpkt.arp.ARP) : 
        if Est_protocole_couche_4(couche_trois.pro) :
            Infos['protocole_4'] = get_proto_name(couche_trois.pro)
        else : 
            Infos['protocole_3'] = get_proto_name(couche_trois.pro)
        Infos['source'] = socket.inet_ntoa(couche_trois.spa)
        Infos['destination'] = socket.inet_ntoa(couche_trois.tpa)
        Infos['ni IP ni ARP'] = False
    elif isinstance(couche_trois, dpkt.ip6.IP6) :
        if Est_protocole_couche_4(couche_trois.nxt) :
            Infos['protocole_4'] = get_proto_name(couche_trois.nxt)
        else : 
            Infos['protocole_3'] = get_proto_name(couche_trois.nxt)
        Infos['ttl'] = couche_trois.hlim
        Infos['source'] = socket.inet_ntoa(couche_trois.src)
        Infos['destination'] = socket.inet_ntoa(couche_trois.dst)
        Infos['ni IP ni ARP'] = False
        if isinstance(couche_trois.data, (dpkt.tcp.TCP, dpkt.udp.UDP, dpkt.sctp.SCTP)):
            Infos['port_src'] = get_service_name(couche_trois.data.sport)
            Infos['port_dst'] = get_service_name(couche_trois.data.dport)
    else :
        #Pour repérer les paquets avec des payloads particuliers
        Infos['ni IP ni ARP'] = True
        #On recherche tout de même une source et une destination dans les couches supérieures
        #  pour pouvoir faire des statistiques plus précises sur les temps de voyage entre les conversations
        #Même si ce cas n'est pas censé arriver souvent, il peut arriver que des paquets aient des payloads Ethernet particuliers 
        # mais contiennent quand même des informations de source et destination dans les couches supérieures
        if isinstance(couche_trois.data, dpkt.tcp.TCP):
            transport = couche_trois.data
        elif isinstance(couche_trois.data, dpkt.udp.UDP):
            transport = couche_trois.data
        elif isinstance(couche_trois.data, dpkt.sctp.SCTP):
            transport = couche_trois.data
        else:
            transport = None

        if transport is not None:
            Infos['port_src'] = get_service_name(transport.sport)
            Infos['port_dst'] = get_service_name(transport.dport)
    return Infos



                      


