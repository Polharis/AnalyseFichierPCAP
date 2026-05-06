<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Mon Dashboard</title>
  <link rel="stylesheet" type="text/css" href="../static/style.css">
  <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
  <script src="../static/script.js"></script>
</head>
<body>
  <h1>Dashboard Analyse Réseau</h1>

  <form id="formulaireFichier" method="GET" enctype="multipart/form-data">
    <label for="fichier_pcap">Fichier pcap à analyser : </label>
    <input type="text" id="fichier_pcap" name="fichier_pcap" placeholder="Ex: /home/user/fichier.pcap">
  </form> <br>
  <span id= "texte_sans_fichier"> (un fichier PCAP par défaut sera séléctionner si le champs est vide) </span>
  <br>
  <br>
  <button name="bouton_options" id="bouton_options" onclick="changer_etat_formulaire()">Ouvrir les options</button>
  <button id ="buttonGraphics" onclick="changer_etat_option_graphique()">Ouvrir les options graphiques</button>
  <button id="genererRapportCsv" onclick="changer_etat_option_rapport_CSV()">Ouvrir les options de rapport CSV</button>
  <button id="buttonStatistics" onclick="changer_etat_option_statistique()">Ouvrir rapport statistique</button>



  <!-- Formulaire caché par défaut -->
  <div id="casePourFiltre">
    <h2>Options d'analyse</h2>
    

        <form id="formulaireFiltre" method = "GET">

            <label>IP uniquement</label>
            <input type="radio" id="proto_filtre" name="proto_filtre" value="ip_only"><br>

            <label>ARP uniquement</label> 
            <input type="radio" id="proto_filtre" name="proto_filtre" value="arp_only"><br>

            <label> Aucun filtre</label> 
            <input type="radio" name="proto_filtre" value="none" checked> <br>

            <input type="text" id = "ip_specifique" name = "ip_specifique" placeholder="IP spécifique à analyser"> <br>

            <input type="text" id = "protocol_specifique" name = "protocol_specifique" placeholder="Protocole à analyser"> <br>

            <input type="text" id = "port_specifique" name = "port_specifique" placeholder="Port à analyser"> <br>

            
        </form>
 </div>

 <div id="casePourGraphique">

    <h2>Liste des graphiques</h2>
    <button id="CoucheDeux" onclick="generer('CoucheDeux')">EtherType</button>
    <button id="CoucheTrois" onclick="generer('CoucheTrois')">CoucheTrois</button>
    <button id="CoucheQuatre" onclick="generer('CoucheQuatre')">CoucheQuatre</button>
    <button id="CoucheServiceSource" onclick="generer('CoucheServiceSource')">CoucheServiceSource</button>
    <button id="CoucheServiceDestination" onclick="generer('CoucheServiceDestination')">CoucheServiceDestination</button>
    <p> graphiques de temps </p>
    <p> formulaire ne s'appliquant que pour les graphiques de temps :</p>
    <form id="formulaireGraphiqueTemps" method = "GET">
        <label for="plage_temps_graphique">Plage de temps en millisecondes pour les graphiques de temps :</label>
        <input type="text" id = "plage_temps_graphique" name = "plage_temps_graphique" placeholder=" 30 millisecondes par défaut"> <br>
    </form>
    <br>
    <br>
    <button id="IntraEspacement" onclick="generer('IntraEspacement')">IntraEspacement, histogramme</button>
    <button id="IntraEspacementRepartition" onclick="generer('IntraEspacementRepartition')">IntraEspacement, courbe de répartition</button>

 </div>

 <div id="casePourStatstique">
    <h2>Liste des statistiques</h2>
    <button id="StatistiqueCoucheDeux" onclick="genererRapportStatistique('CoucheDeux')">CoucheDeux</button>
    <button id="StatistiqueCoucheTrois" onclick="genererRapportStatistique('CoucheTrois')">CoucheTrois</button>
    <button id="StatistiqueCoucheServiceSource" onclick="genererRapportStatistique('CoucheServiceSource')">CoucheServiceSource</button>
    <button id="StatistiqueCoucheServiceDestination" onclick="genererRapportStatistique('CoucheServiceDestination')">CoucheServiceDestination</button>
</div>

<div id="casePourRapportCSV">
    <h2>Génération du rapport CSV</h2>
    <button id="genererRapportCsv" onclick="genererRapportCsv()">Générer un rapport CSV générale</button>
    <p> Rapport CSV sur les statistiques de temps </p>
</div>


    
 <!--   fin du formulaire-->
      

  <p id="chargement">Génération en cours...</p>
  <p id="erreur"></p>
  <p id="succesCSV">Le rapport CSV à bien été généré. Il est trouvable dans le dossier DataOutput du projet git</p>

  <div id="graphique" style="width:100%; height:600px;"></div>
  <div id="statistique" style="width:100%; height:600px;"></div>
  
</body>
</html>