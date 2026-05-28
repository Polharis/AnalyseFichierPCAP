import matplotlib.pyplot as plt
import pandas as pd


#pour plotly
import plotly.graph_objects as go



def statistiqueSousgraphique(stats_table, graph_type) : 
    #Cette fonction prend en entrée une table de statistiques et retourne un graphique 
    # Réaliser avec plotly pour retourner du JSON

    """
    Crée un graphique en camembert représentant la composition
    des paquets traités, à partir d'une table de statistiques.

    Les valeurs inférieures à 0.5% sont regroupées dans une
    catégorie "Other" pour améliorer la lisibilité. La clé
    total_paquet est supprimée avant la construction du graphique.
    Le graphique est généré avec Plotly et retourné en JSON
    pour une réutilisation côté JavaScript.

    Args:
        stats_table (dict): Dictionnaire contenant les informations
                            à représenter graphiquement.
        graph_type (str): Type de graphique à afficher, détermine
                          quelles informations extraire de stats_table
                          (ex: "CoucheServiceDestination",
                          "CoucheServiceSource", "CoucheDeux", etc.).

    Returns:
        str: Chaîne JSON contenant le graphique Plotly,
             réutilisable côté JavaScript via plotly.js.

    Raises:
        KeyError: Si stats_table ne contient pas les clés attendues.
        ValueError: Si stats_table est vide après filtrage.
    """
    stats_table.pop("total_paquet", None)
    liste_cle_a_supprimer = []
    for key in stats_table.keys() :
        if stats_table[key] < 0.5 :
            liste_cle_a_supprimer.append(key)
    for key in liste_cle_a_supprimer :
        stats_table.setdefault("Other", 0)
        stats_table["Other"] += stats_table[key]
        stats_table.pop(key, None)

    # Déterminer le type d'information
    if graph_type == "CoucheServiceDestination" or graph_type == "CoucheServiceSource" :
        information = "services"
    else : 
        information = "protocoles"

    # Créer le graphique en camembert avec Plotly
    fig = go.Figure(data=[go.Pie(
        labels=list(stats_table.keys()),
        values=list(stats_table.values()),
        textposition='inside',
        textinfo='percent+label'
    )])

    fig.update_layout(
        title=f"Graphique des statistiques de la {graph_type}",
        xaxis_title=f"Pourcentage de {information} sur l'ensemble des paquets"
    )

    return fig.to_json()


#Créer un histogramme de l'inter-espacement entre les paquets pour chaque conversation (src, dst)
def histogrammeIntraEspacement(dicoReseau,plage_temps_graphique) :
    """
    Crée un histogramme représentant les intra-espacements entre
    les paquets pour chaque conversation (src, dst).

    Chaque conversation génère une trace distincte superposée
    sur le même graphique (barmode overlay) avec une opacité
    de 0.6 pour améliorer la lisibilité.

    Args:
        dicoReseau (dict): Dictionnaire dont les clés sont des tuples
                           (src, dst) et les valeurs des listes de
                           timestamps représentant les espacements
                           entre paquets.
        plage_temps_graphique (int): Taille des intervalles en
                                     millisecondes pour le regroupement
                                     des paquets ayant le même src/dst
                                     et espacés de plage_temps.

    Returns:
        str: Chaîne JSON contenant le graphique Plotly,
             réutilisable côté JavaScript via plotly.js.

    Raises:
        ValueError: Si dicoReseau est vide ou ne contient
                    que des listes vides.
    """

    fig = go.Figure()

    for (src, dst, port_src, port_dst, proto), times in dicoReseau.items():
        if not times:
            continue
        fig.add_trace(go.Histogram(
            x=times,
            name=f"{src} → {dst} + {port_src} → {port_dst} + {proto}",
            opacity=0.6,
            xbins=dict(size=plage_temps_graphique)  
        ))

    fig.update_layout(
        title="Histogramme des inter-espacements par conversation",
        xaxis_title="Inter-espacement (millisecondes)",
        yaxis_title="Nombre d'intervalles",
        barmode='overlay'
    )

    return fig.to_json()

def courbeRepartitionIntraInterEspacement(dicoReseau,plage_temps_graphique,inter_ou_intra) :
    """
    Crée une courbe de répartition cumulative des intra-espacements
    pour tous les couples d'IP mélangés.

    Les temps sont extraits de toutes les conversations, triés,
    puis regroupés par intervalles de plage_temps_graphique
    millisecondes. Les occurrences sont ensuite converties en
    pourcentages cumulatifs pour former la courbe de répartition.

    Args:
        dicoReseau (dict): Dictionnaire dont les clés sont des tuples
                           (src, dst) et les valeurs des listes de
                           timestamps représentant les espacements
                           entre paquets.
        plage_temps_graphique (int): Taille des intervalles en
                                     millisecondes pour le regroupement
                                     des résultats.

    Returns:
        str: Chaîne JSON contenant le graphique Plotly,
             réutilisable côté JavaScript via plotly.js.

    Raises:
        ZeroDivisionError: Si dicoReseau est vide (total = 0).
        ValueError: Si plage_temps_graphique est égal à zéro.
    """

    fig = go.Figure()

    liste_temps = []
    dico_temps_pourcent = {}

    if inter_ou_intra == "intra" :
        for valeures in dicoReseau.values():
            for temps in valeures : 
                liste_temps.append(temps)
        liste_temps.sort()
    else :
        liste_temps = dicoReseau
        liste_temps.sort()
    
    # Regrouper les temps par plage_temps_graphique et compter les occurrences
    for temps in liste_temps :
        temps_arrondi = round(temps / plage_temps_graphique) * plage_temps_graphique
        dico_temps_pourcent.setdefault(temps_arrondi, 0)
        dico_temps_pourcent[temps_arrondi] += 1
    
    # Calculer les pourcentages
    total = len(liste_temps)
    for temps_arrondi in dico_temps_pourcent :
        dico_temps_pourcent[temps_arrondi] = (dico_temps_pourcent[temps_arrondi] / total) * 100
    
    # Trier le dictionnaire par temps
    temps_tries = sorted(dico_temps_pourcent.keys())
    pourcentages = [dico_temps_pourcent[t] for t in temps_tries]
    
    # Calculer les pourcentages cumulatifs
    cumulative = []
    cumul = 0
    for pourcent in pourcentages :
        cumul += pourcent
        cumulative.append(cumul)
    
    # Ajouter la courbe de répartition cumulative
    fig.add_trace(go.Scatter(
        x=temps_tries,
        y=cumulative,
        mode='lines+markers',
        name='Répartition cumulative',
        line=dict(color='blue', width=2)
    ))
    
    if inter_ou_intra == "intra" :
        fig.update_layout(
            title="Courbe de répartition cumulative des intra-espacements",
            xaxis_title="Intra-espacement (millisecondes)",
            yaxis_title="Pourcentage cumulatif (%)",
            hovermode='x unified'
        )
    else : 
        fig.update_layout(
            title="Courbe de répartition cumulative des inter-espacements",
            xaxis_title="Inter-espacement (millisecondes)",
            yaxis_title="Pourcentage cumulatif (%)",
            hovermode='x unified'
        )

    return fig.to_json()


def courbeDensiteDeProbaIntra (dicoReseau,plage_temps_graphique,inter_ou_intra) : 

    fig = go.Figure()

    liste_temps = []
    dico_temps_pourcent = {}

    if inter_ou_intra == "intra" :
        for valeures in dicoReseau.values():
            for temps in valeures : 
                liste_temps.append(temps)
        liste_temps.sort()
    else :
        liste_temps = dicoReseau
        liste_temps.sort()
    
    # Regrouper les temps par plage_temps_graphique et compter les occurrences
    for temps in liste_temps :
        temps_arrondi = round(temps / plage_temps_graphique) * plage_temps_graphique
        dico_temps_pourcent.setdefault(temps_arrondi, 0)
        dico_temps_pourcent[temps_arrondi] += 1
    
    # Calculer les pourcentages
    total = len(liste_temps)
    for temps_arrondi in dico_temps_pourcent :
        dico_temps_pourcent[temps_arrondi] = (dico_temps_pourcent[temps_arrondi] / total) * 100
    
    # Trier le dictionnaire par temps
    temps_tries = sorted(dico_temps_pourcent.keys())
    pourcentages = [dico_temps_pourcent[t] for t in temps_tries]

    # Ajouter la courbe de densité
    fig.add_trace(go.Scatter(
        x=temps_tries,
        y=pourcentages,
        mode='lines+markers',
        name='Répartition de densité',
        line=dict(color='blue', width=2)
    ))
    print(temps_tries)
    if inter_ou_intra == "intra" :
        fig.update_layout(
            title="Courbe de densité de probabilité des intra-espacements",
            xaxis_title="Intra-espacement (millisecondes)",
            yaxis_title="Pourcentage (%)",
            hovermode='x unified'
        )
    else : 
        fig.update_layout(
            title="Courbe de densité de probabilité des inter-espacements",
            xaxis_title="Inter-espacement (millisecondes)",
            yaxis_title="Pourcentage (%)",
            hovermode='x unified'
        )

    return fig.to_json()

def courbeRepartitionInterFull(dicoReseau,plage_temps_graphique) :
    fig = go.Figure()

    dico_temps = {}

    # Regrouper les temps par plage_temps_graphique et compter les occurrences
    for temps in dicoReseau :
        temps_arrondi = round(temps / plage_temps_graphique) * plage_temps_graphique
        dico_temps.setdefault(temps_arrondi, 0)
        dico_temps[temps_arrondi] += 1

   # Calculer les pourcentages
    total = len(dicoReseau)
    for temps_arrondi in dico_temps :
        dico_temps[temps_arrondi] = (dico_temps[temps_arrondi] / total) * 100
    
    # Trier le dictionnaire par temps
    temps_tries = sorted(dico_temps.keys())
    pourcentages = [dico_temps[t] for t in temps_tries]
    
    # Calculer les pourcentages cumulatifs
    cumulative = []
    cumul = 0
    for pourcent in pourcentages :
        cumul += pourcent
        cumulative.append(cumul)
    
    # Ajouter la courbe de répartition cumulative
    fig.add_trace(go.Scatter(
        x=temps_tries,
        y=cumulative,
        mode='lines+markers',
        name='Répartition cumulative des full inter-espacements',
        line=dict(color='blue', width=2)
    ))
    

    fig.update_layout(
            title="Courbe de répartition cumulative des full inter-espacements",
            xaxis_title="temps en millisecondes",
            yaxis_title="Pourcentage (%)",
            hovermode='x unified'
        )
    
    return fig.to_json()

def histogrammeDensiteTaille(liste_taille) :
    fig = go.Figure()

    # Regrouper les tailles par intervalle de 50 et compter les occurrences
    dico_tailles = {}
    for taille in liste_taille:
        taille_arrondie = round(taille / 50) * 50
        #conversion en octet
        taille_arrondie = taille_arrondie / 50
        dico_tailles.setdefault(taille_arrondie, 0)
        dico_tailles[taille_arrondie] += 1
    
    # Calculer les pourcentages
    total = len(liste_taille)
    for taille_arrondie in dico_tailles:
        dico_tailles[taille_arrondie] = (dico_tailles[taille_arrondie] / total) * 100
    
    # Trier par taille
    tailles_triees = sorted(dico_tailles.keys())
    pourcentages = [dico_tailles[t] for t in tailles_triees]
    
    fig.add_trace(go.Bar(
        x=tailles_triees,
        y=pourcentages,
        name="Histogramme de densité de taille de paquets",
        opacity=0.6
    ))

    fig.update_layout(
        title="Histogramme de densité de taille de paquets",
        xaxis_title="Taille du paquet (octets)",
        yaxis_title="Pourcentage (%)",
        barmode='overlay'
    )

    return fig.to_json()

def courbeDebitTaille(liste_taille_temps,plage_temps_graphique) :
    fig = go.Figure()

    taille_par_temps = {}

    for taille, temps in liste_taille_temps:
        temps_arrondi = round(temps / plage_temps_graphique) * plage_temps_graphique
        
        taille_par_temps.setdefault(temps_arrondi, 0)
        taille_par_temps[temps_arrondi] += taille
    # Trier par temps
    temps_finaux = []
    temps_tries = sorted(taille_par_temps.keys())
    taille_triee = []
    for temps in temps_tries : 
        taille_triee.append(taille_par_temps[temps] / 50)
    for temps in temps_tries :
        temps_finaux.append(temps - temps_tries[0])
    
    fig.add_trace(go.Scatter(
        x=temps_finaux,
        y=taille_triee,
        mode='lines+markers',
        name="Courbe de débit en fonction de la taille des paquets",
        line=dict(color='blue', width=2)
    ))

    fig.update_layout(
        title="Courbe de débit en fonction de la taille des paquets",
        xaxis_title="Temps (millisecondes)",
        yaxis_title="Débit (octets)",
        hovermode='x unified'
    )

    return fig.to_json()


#----------------------------------------------------------------------------------------------------
# ----------------------- A mettre entre parenthèse car je n'ai pas tout les outils -----------------

def statistiqueTempsVoyageMoyenSousgraphique(stats_table) : 
    #Cette fonction prend en entrée une table de statistiques et retourne un graphique 
    # Réaliser avec panda se servant de matplotlib pour faire le graphique
    graph = pd.Series(stats_table[0])
    graph.plot(kind="bar")
    plt.title("Graphique moyenne de temps pris pour les aller-retour entre les différentes conversations")
    plt.xlabel("Conversations")
    plt.ylabel("Moyenne du temps de voyage (en secondes)")
    plt.tight_layout()
    plt.show()

def statistiqueTempsVoyageUnitaireSousgraphique(table_temps) :
    # table_temps : {(src, dst): [temps]}
    # Pour chaque couple source/destination, on trace la courbe cumulative des temps de voyage unitaire.
    fig, ax = plt.subplots()
    liste_temps = []

    for (src, dst), times in table_temps.items() :
        if not times :
            continue
        liste_temps.append(times)
        max_progressif = pd.Series(liste_temps).cummax()
        ax.plot(
            range(1, len(max_progressif) + 1),
            max_progressif,
            marker='o',
            label=f"{src} → {dst}"
        )

    ax.set_title("Graphique du temps maximum progressif par conversation")
    ax.set_xlabel("Nombre de paquets")
    ax.set_ylabel("Temps maximum trouvé (secondes)")
    ax.legend(loc="best", fontsize="small")
    ax.grid(True)
    plt.tight_layout()
    plt.show()

def statistiqueTempsVoyageRepartitionSousgraphique(table_temps) :
    # table_temps : {(src, dst): [temps]}
    # On trace la répartition des temps de voyage unitaire pour chaque conversation.
    fig, ax = plt.subplots()

    for (src, dst), times in table_temps.items() :
        if not times : 
            continue
        ax.plot(
            range(1, len(times) + 1),
            times,
            marker='o',
            label=f"{src} → {dst}"
        )

    ax.set_title("Graphique de la répartition des temps de voyage unitaire par conversation")
    ax.set_xlabel("Nombre de paquets")
    ax.set_ylabel("Temps de voyage unitaire (secondes)")
    ax.legend(loc="best", fontsize="small")
    ax.grid(True)
    plt.tight_layout()
    plt.show()

    return None