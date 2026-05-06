from flask import Flask, render_template, request, jsonify
import matplotlib
matplotlib.use('Agg')  # Important : mode sans affichage
import matplotlib.pyplot as plt

import scriptPy.graphiques.creationGraphiques as graphiques
from scriptPy.LectureDonne import optionsArgParse as options
import  scriptPy.LectureDonne.lectureDonneFichierUnique as recupDico  
import scriptPy.main as main




app = Flask(__name__)



@app.route('/')
def index():
    return render_template('index.php')  

@app.route('/generer', methods=['POST'])
def generer():
    
    #Application des filtres
    params = request.get_json(force=True, silent=True) or {}
    main.configurerParams(params)
    #-------------------------------------

    typeGraphique = params.get('typeGraphique', None)

    plage_temps_graphique = params.get('plage_temps_graphique', None)

    if plage_temps_graphique is None :
        plage_temps_graphique = 30 # valeur par défaut de la plage de temps pour les graphiques de temps
    elif plage_temps_graphique is not int :
        try :
            plage_temps_graphique = int(plage_temps_graphique)
        except ValueError :
            plage_temps_graphique = 30 # valeur par défaut de la plage de temps pour les graphiques de temps
    elif plage_temps_graphique <= 0 or plage_temps_graphique > 700 :
        plage_temps_graphique = 30 # valeur par défaut de la plage de temps pour les graphiques de temps
 

    fig = main.genererGraphique(typeGraphique,plage_temps_graphique)

 

    if fig is None:
        return jsonify({ 'success': False, 'error': 'Aucune donnée disponible.' })

    return jsonify({ 'success': True, 'graphique': fig })  


@app.route('/genererRapportCsv', methods=['POST'])
def generer_csv():
    #Application des filtres
    params = request.get_json(force=True, silent=True) or {}
    main.configurerParams(params)
    #-------------------------------------
    typeGraphique = params.get('typeGraphique', None)

    

    main.genererRapportCsv()

    return jsonify({ 'success': True})  


@app.route('/genererRapportStatistique', methods=['POST'])
def genererRapportStatistique():
    #Application des filtres
    params = request.get_json(force=True, silent=True) or {}
    main.configurerParams(params)
    #-------------------------------------
    mode = params.get('typeStatistique', None)
    
    
    fig = main.genererRapportStatistique(mode)

    if fig is None:
        return jsonify({ 'success': False, 'error': 'Aucune donnée disponible.' })

    return jsonify({ 'success': True, 'statistique': fig })   


# adresse : http://localhost:5000/
app.run(debug=True, host='127.0.0.1', port=5000)


#liste chemin du fichier PCAP à analyser
#/home/stagetesa/Downloads/NMAP_PROBE.pcap
#/home/stagetesa/Downloads/a1_res0.pcap
#/home/stagetesa/Downloads/transfer_12517082_files_0bb119a5/c3_res13.pcap
#/home/stagetesa/Downloads/transfer_12517082_files_0bb119a5/obs1_res15.pcap

#liste filtre 
#CoucheDeux
#CoucheTrois
#CoucheServiceSource
#CoucheServiceDestination
#InterEspacement

#liste graphique
#CoucheDeux
#CoucheTrois
#CoucheServiceSource
#CoucheServiceDestination   