<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Mon Dashboard</title>
  <link rel="stylesheet" type="text/css" href="../static/style.css">
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">

  <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
  <script src="../static/script.js"></script>
</head>

<body>

  <div id="caseCheminFichier" class="text-center d-flex flex-column align-items-center" >
    <h1>Dashboard Analyse Réseau </h1>

      <form id="formulaireFichier" method="GET" enctype="multipart/form-data">
        <label for="fichier_pcap">Fichier pcap à analyser : </label>
        <input type="text" id="fichier_pcap" name="fichier_pcap" placeholder="Ex: /home/user/fichier.pcap">
      </form>

      <div style="padding: 20px;">
        <button id="appliquerChemin" onclick="regenererGraphiques()">Appliquer</button>
        <div id="chargementIcon" class="cache spinner-border" role="status"></div>
        <span id = "chargementTexte" class="cache">Chargement... du fichier PCAP</span>
      </div>

    <p id="erreur"></p>
  </div>

  <div class="container-fluid ">

    <div class="d-flex align-items-center gap-3">
      <div id = "topTalker"> 
        <div id = "topIpDst"> </div>
      </div>
    </div>
    <div class="d-flex align-items-center gap-3">

      <div id = "topTalker"> 
        <div id = "topIpSrc"> </div>
      </div>

      <div id="nombrePaquet">
        <div id="afficherNombrePaquet"></div>
      </div>

      <div id="detectionAnomalie" class ="cache">
        <span> coucou </span>
      </div>

    </div>

    <div id= "caseGeneral">

      

      <!-- Div gauche : 1/3 de large, s'étend sur 3 lignes -->
      

      <div id = "caseElementEtParametre">
  
        <div id="casePourFiltre">
          <h2>Paramètres</h2>
          
            <form id="formulaireFiltre" method = "GET">

              <input type="text" id = "ip_specifique" name = "ip_specifique" placeholder="IP spécifique à analyser"> <br>

              <input type="text" id = "protocol_specifique" name = "protocol_specifique" placeholder="Protocole à analyser"> <br>

              <input type="text" id = "port_specifique" name = "port_specifique" placeholder="Port à analyser"> <br>

              <label for="plage_temps_graphique">Plage de temps en millisecondes pour les graphiques de temps :</label>
              <input type="text" id = "plage_temps_graphique" name = "plage_temps_graphique" placeholder=" 30 millisecondes par défaut"> <br>
  
              </form>
        </div>

        <div id="listeFlux">
          <h2>Liste des flux</h2>
          <div id="conteneurFlux" style="white-space: pre-wrap; width:100%; height:550px; overflow-y: auto;"></div>
        </div>

        <div id="listeTypeGraphique">
          <h2> Liste graphiques</h2>
          <form id="formulaireListeGraphiques" method = "GET">
            <label for ="graphiqueHistogrammeIntra"> histogramme des intra-espacements </label>
            <input type="checkbox" id ="graphiqueHistogrammeIntra" name ="graphiqueHistogrammeIntra"><br>

            <label for="graphiqueCumulatifIntra"> Courbe cumultive des intra-espacements </label>
            <input type="checkbox" id="graphiqueCumulatifIntra" name="graphiqueCumulatifIntra"><br>

            <label for="graphiqueCumulatifInter"> Courbe cumultive des inter-espacements </label>
            <input type="checkbox" id="graphiqueCumulatifInter" name="graphiqueCumulatifInter"><br>
          </form>
        </div>
      </div>

        <!-- Carousel à droite -->
      <div id="caseCarousel" style="grid-column: 2; grid-row: 1 / span 3;">
        <div id="carouselGraphiques" class="carousel slide h-100" data-ride="carousel" data-interval="false">
          
          <!-- Indicateurs -->
          <ol class="carousel-indicators">
            <li data-target="#carouselGraphiques" data-slide-to="0" class="active"></li>
            <li data-target="#carouselGraphiques" data-slide-to="1"></li>
            <li data-target="#carouselGraphiques" data-slide-to="2"></li>
            <li data-target="#carouselGraphiques" data-slide-to="3"></li>
            <li data-target="#carouselGraphiques" data-slide-to="4"></li>
          </ol>

          <!-- Slides -->
          <div class="carousel-inner h-100">
            <div class="carousel-item active h-100">
              <div id="graphiqueEtherType" style="width:100%; height:100%;"></div>
              <div class="carousel-caption"><h5>EtherType</h5></div>
            </div>
            <div class="carousel-item h-100">
              <div id="graphiqueCoucheTrois" style="width:100%; height:100%;"></div>
              <div class="carousel-caption"><h5>Couche 3</h5></div>
            </div>
            <div class="carousel-item h-100">
              <div id="graphiqueCoucheQuatre" style="width:100%; height:100%;"></div>
              <div class="carousel-caption"><h5>Couche 4</h5></div>
            </div>
            <div class="carousel-item h-100">
              <div id="graphiqueServiceSource" style="width:100%; height:100%;"></div>
              <div class="carousel-caption"><h5>Service Source</h5></div>
            </div>
            <div class="carousel-item h-100">
              <div id="graphiqueServiceDestination" style="width:100%; height:100%;"></div>
              <div class="carousel-caption"><h5>Service Destination</h5></div>
            </div>
          </div>

          <!-- Boutons précédent/suivant -->
          <a class="carousel-control-prev" href="#carouselGraphiques" role="button" data-slide="prev">
            <span class="carousel-control-prev-icon"></span>
          </a>
          <a class="carousel-control-next" href="#carouselGraphiques" role="button" data-slide="next">
            <span class="carousel-control-next-icon"></span>
          </a>

          </div>
        </div>

      </div>

      

    </div>
    <button id="appliquerParams" onclick='appliquerGraphs()'>Appliquer</button>
    <div id="afficherGraphiqueHistogrammeIntra" style="width:100%; height:100%;"></div>
    <div id="afficherGraphiqueCumulatifeIntra" style="width:100%; height:100%;"></div>
    <div id="afficherGraphiqueCumulatifeInter" style="width:100%; height:100%;"></div>
  </div>

  <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>