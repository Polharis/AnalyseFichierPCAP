<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Mon Dashboard</title>
  <link rel="stylesheet" type="text/css" href="../static/style.css">
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">

  <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
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

      <div id="detectionAnomalie" class="cache">
        <button id ="bouttonAnomalie" onclick="openAnomaliePopUp()"> Anomalie détéctée, cliqué pour plus de détails </button> 
      </div>

    </div>

    <div id= "caseGeneral">

      

      <!-- Div gauche : 1/3 de large, s'étend sur 3 lignes -->
      

      <div id = "caseElementEtParametre">
  
        <div id="casePourFiltre">
          <h2>Paramètres</h2>
          <div id="carouselParametre" class="carousel slide h-75" data-ride="carousel" data-interval="false">
          
            <!-- Indicateurs -->
            <ol class="carousel-indicators">
              <li data-target="#carouselParametre" data-slide-to="0" class="active"></li>
              <li data-target="#carouselParametre" data-slide-to="1"></li>
              <li data-target="#carouselParametre" data-slide-to="2"></li>
              <li data-target="#carouselParametre" data-slide-to="3"></li>
              <li data-target="#carouselParametre" data-slide-to="4"></li>
            </ol>

            <!-- Slides -->
            <div class="carousel-inner h-100">
              <div class="carousel-item active h-100">
                <h3> Premier flux : </h3>

                <form id="formulaireFiltreUn" method = "GET">

                  <input type="text" id = "ip_specifique_src_un" name = "ip_specifique_src_un" placeholder="IP source à analyser"> <br>

                  <input type="text" id = "ip_specifique_dst_un" name = "ip_specifique_dst_un" placeholder="IP destination à analyser"> <br>

                  <input type="text" id = "port_specifique_src_un" name = "port_specifique_src_un" placeholder="Port source à analyser"> <br>

                  <input type="text" id = "port_specifique_dst_un" name = "port_specifique_dst_un" placeholder="Port destination à analyser"> <br>

                  <input type="text" id = "protocol_specifique_un" name = "protocol_specifique_un" placeholder="Protocole à analyser"> <br>

                  </form>

                </div>
              <div class="carousel-item h-100">
                <h3> Deuxième flux : </h3>

                <form id="formulaireFiltreDeux" method = "GET">

                  <input type="text" id = "ip_specifique_src_deux" name = "ip_specifique_src_deux" placeholder="IP source à analyser"> <br>

                  <input type="text" id = "ip_specifique_dst_deux" name = "ip_specifique_dst_deux" placeholder="IP destination à analyser"> <br>

                  <input type="text" id = "port_specifique_src_deux" name = "port_specifique_src_deux" placeholder="Port source à analyser"> <br>

                  <input type="text" id = "port_specifique_dst_deux" name = "port_specifique_dst_deux" placeholder="Port destination à analyser"> <br>

                  <input type="text" id = "protocol_specifique_deux" name = "protocol_specifique_deux" placeholder="Protocole à analyser"> <br>

                  </form>

              </div>
            </div>

            <!-- Boutons précédent/suivant -->
            <a class="carousel-control-prev carousel-parametre-gauche" href="#carouselParametre" role="button" data-slide="prev">
              <span class="carousel-control-prev-icon"></span>
            </a>
            <a class="carousel-control-next carousel-parametre-droit" href="#carouselParametre" role="button" data-slide="next">
              <span class="carousel-control-next-icon"></span>
            </a>
          </div>

          <form id="filtreGlobal" maethod = "GET">
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

            <label for = "graphiqueDensiteDeProbaIntra"> Courbe de densité de probabilité des intra-espacements</label>
            <input type="checkbox" id="graphiqueDensiteDeProbaIntra" name="graphiqueDensiteDeProbaIntra"><br>

            <label for="graphiqueCumulatifInter"> Courbe cumultive des inter-espacements </label>
            <input type="checkbox" id="graphiqueCumulatifInter" name="graphiqueCumulatifInter"><br>

            <label for = "graphiqueDensiteDeProbaInter"> Courbe de densité de probabilité des intra-espacements</label>
            <input type="checkbox" id="graphiqueDensiteDeProbaInter" name="graphiqueDensiteDeProbaInter"><br>

            <label for = "graphiqueRepartitionInterFull"> Courbe de répartition cumulative des Full inter-espacements</label>
            <input type="checkbox" id="graphiqueRepartitionInterFull" name="graphiqueRepartitionInterFull"><br>
            
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

    <div id ="caseGraphiqueHistogrammeIntra" >
        <div id="afficherGraphiqueHistogrammeIntra" style="width:1800px; height:500px;"></div>
        <button id="bouttonHistogrammeIntra" OnClick="genererRapportCsv('intraEspacement')">  extraire suite temporelle </button>
        <span id="succesCSV" class="cache">Le rapport CSV a été généré avec succès !</span>
    </div>

    <div id="caseGraphiqueCumulatifIntra" >
      <button id="bouttonCumulatifeIntra" OnClick="genererRapportCsv('intraEspacement')">  extraire suite temporelle </button>
      <div id="afficherGraphiqueCumulatifeIntra" style=" height:400px;"></div>
    </div>

    <div id="caseGraphiqueDensiteIntra" >
      <button id="bouttonDensiteIntra" OnClick="genererRapportCsv('intraEspacement')">  extraire suite temporelle </button>
      <div id ="afficherGraphiqueDensiteIntra" style=" height:400px;"></div>
    </div>

    <div id="caseGraphiqueCumulatifeInter" >
      <button id="bouttonCumulatifeInter" OnClick="genererRapportCsv('interEspacement')">  extraire suite temporelle </button>
      <span id="interEspacementRepartitionSuccesCSV" class="cache">Le rapport CSV a été généré avec succès !</span>
      <div id="afficherGraphiqueCumulatifeInter" style=" height:400px;"></div>
    </div>

    <div id ="caseGraphiqueDensiteInter" >
      <button id="bouttonDensiteInter" OnClick="genererRapportCsv('interEspacement')">  extraire suite temporelle </button>
      <div id ="afficherGraphiqueDensiteInter" style=" height:400px;"></div>
    </div>

    <div id="caseGraphiqueRepartitionInterFull" >
      <button id="bouttonRepartitionInterFull" OnClick="genererRapportCsv('interFullEspacement')">  extraire suite temporelle </button>
      <span id="interFullEspacementRepartitionSuccesCSV" class="cache">Le rapport CSV a été généré avec succès !</span>
      <div id ="afficherGraphiquecumulatifInterFull" style=" height:400px;"></div>
    </div>
    
  </div>

  <div id="overlay">
    <div id="modal">
      <h2>Attention !</h2>
      <div id="texteScanPort"></div>
    </div>
  </div>

  <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>