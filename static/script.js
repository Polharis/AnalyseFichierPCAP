
document.addEventListener("DOMContentLoaded", async function() {
    
    document.getElementById('caseGraphiqueHistogrammeIntra').style.display = 'none'
    document.getElementById('caseGraphiqueCumulatifIntra').style.display = 'none'
    document.getElementById('caseGraphiqueDensiteIntra').style.display = 'none'
    document.getElementById('caseGraphiqueCumulatifeInter').style.display = 'none'
    document.getElementById('caseGraphiqueDensiteInter').style.display = 'none'
    document.getElementById('caseGraphiqueRepartitionInterFull').style.display = 'none'
    document.getElementById('caseHistogrammeDensiteTaille').style.display = 'none'
    document.getElementById('caseDebitTaille').style.display = 'none'
    document.getElementById("texteScanPort").textContent = ""
    document.getElementById("texteReemissionPaquet").textContent = ""

    icon = document.getElementById('chargementIcon')
    texte = document.getElementById('chargementTexte')
    alerteAnomalie = document.getElementById('detectionAnomalie');
    seconde_fichier_pcap = document.getElementById('fichier_pcap_deux').value;
    alerteAnomalie.classList.add('cache'); 
    icon.classList.remove('cache');
    texte.classList.remove('cache');
    
    if (seconde_fichier_pcap != null && seconde_fichier_pcap !== "") {
          await genererRapportAvecDeuxFichiers()
          texte.textContent = "Chargement... des fichiers PCAP"
        }
    
    texte.textContent = "Chargement... du fichier PCAP"
    await generer('CoucheDeux',"graphiqueEtherType");
    texte.textContent = "Chargement... du graphique CoucheTrois"
    await generer('CoucheTrois',"graphiqueCoucheTrois");
    texte.textContent = "Chargement... du graphique CoucheQuatre"
    await generer('CoucheQuatre',"graphiqueCoucheQuatre");
    texte.textContent = "Chargement... du graphique graphiqueServiceSource"
    await generer('CoucheServiceSource',"graphiqueServiceSource");
    texte.textContent = "Chargement... du graphique graphiqueServiceDestination"
    await generer('CoucheServiceDestination',"graphiqueServiceDestination");
    texte.textContent = "Chargement... de la détection d'anomalie (Scan de port)"
    await genererDetectionAnomalie('scanPort','texteScanPort')
    texte.textContent = "Chargement... de la détection d'anomalie (Réemission TCP)"
    await genererDetectionAnomalie('reemissionTcp','texteReemissionPaquet')
    texte.textContent = "Chargement... de la liste de flux"
    await genererRapportStatistique('flux',"conteneurFlux");
    texte.textContent = "Chargement... de l'ip src la plus active"
    await genererRapportStatistique('ipPlusActiveSrc',"topIpSrc");
    texte.textContent = "Chargement... de l'ip dst la plus active"
    await genererRapportStatistique('ipPlusActiveDst',"topIpDst");
    texte.textContent = "Chargement... du nombre de paquet"
    await genererRapportStatistique('nbPaquet',"afficherNombrePaquet");

    icon.classList.add('cache');
    texte.classList.add('cache');
});

    async function appliquerGraphs(){

        await regenererGraphiques();
        histogrammeIntra = document.getElementById('graphiqueHistogrammeIntra');
        cumulatifIntra = document.getElementById('graphiqueCumulatifIntra');
        densiteProbaIntra = document.getElementById('graphiqueDensiteDeProbaIntra')
        cumulatifInter = document.getElementById('graphiqueCumulatifInter');
        densiteProbaInter = document.getElementById('graphiqueDensiteDeProbaInter');
        cumulatifInterFull = document.getElementById('graphiqueRepartitionInterFull');
        histogrammeDensiteTaille = document.getElementById('histogrammeDensiteTaille');
        courbeDebitTaille = document.getElementById('courbeDebitTaille');


        icon = document.getElementById('chargementIcon')
        texte = document.getElementById('chargementTexte')

        icon.classList.remove('cache');
        texte.classList.remove('cache');

        if(histogrammeIntra.checked){
            texte.textContent = "Chargement... du graphique HistogrammeIntra"
            await generer('IntraEspacement',"afficherGraphiqueHistogrammeIntra");
            document.getElementById('caseGraphiqueHistogrammeIntra').style.display = 'block'
        }else{
            document.getElementById('caseGraphiqueHistogrammeIntra').style.display = 'none'
        }
        if(cumulatifIntra.checked){
            texte.textContent = "Chargement... du graphique répartition cumulative intra"
            await generer('IntraEspacementRepartition',"caseGraphiqueCumulatifIntra");
        }else{
            document.getElementById('caseGraphiqueCumulatifIntra').style.display = 'none'
        }

        if(densiteProbaIntra.checked){
            texte.textContent = "Chargement... du graphique de densité de probbilté intra"
            await generer('IntraEspacementDensite',"caseGraphiqueDensiteIntra");
        }else{
            document.getElementById('caseGraphiqueDensiteIntra').style.display = 'none'
        }

        if(cumulatifInter.checked){
            texte.textContent = "Chargement... du graphique répartition cumulative inter"
            await generer('InterEspacementRepartition',"caseGraphiqueCumulatifeInter");
        }else{
            document.getElementById('caseGraphiqueCumulatifeInter').style.display = 'none'
        }

        if(densiteProbaInter.checked){
          texte.texteContent = "Chargement... du graphique de densité de probabilité inter"
          await generer('InterEspacementDensite','caseGraphiqueDensiteInter')
        }else{
          document.getElementById('caseGraphiqueDensiteInter').style.display = 'none'
        }

        if(cumulatifInterFull.checked){
          texte.texteContent = "Chargement... du graphique de répartition cumulative des full inter-espacement"
          await generer('interFullEspacementRepartition','caseGraphiqueRepartitionInterFull')
        }else{
          document.getElementById('caseGraphiqueRepartitionInterFull').style.display = 'none'
        }

        if(histogrammeDensiteTaille.checked){
          texte.texteContent = "Chargement... du graphique de répartition cumulative des full inter-espacement"
          await generer('histogrammeDensiteTaille','caseHistogrammeDensiteTaille')
        }else{
          document.getElementById('caseHistogrammeDensiteTaille').style.display = 'none'
        }

        if(courbeDebitTaille.checked){
          texte.texteContent = "Chargement... du graphique de débit en fonction de la taille des paquets"
          await generer('debit_taille','caseDebitTaille')
        }else{
          document.getElementById('caseDebitTaille').style.display = 'none'
        }

        icon.classList.add('cache');
        texte.classList.add('cache');
    } 


    async function genererRapportCsv(mode) {
      try {

        // Affiche le message de chargement

        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const ip_specifique_src_un = document.getElementById('ip_specifique_src_un').value;
        const ip_specifique_dst_un = document.getElementById('ip_specifique_dst_un').value;
        const protocol_specifique_un = document.getElementById('protocol_specifique_un').value;
        const port_specifique_src_un = document.getElementById('port_specifique_src_un').value;
        const port_specifique_dst_un = document.getElementById('port_specifique_dst_un').value;
        const ip_specifique_src_deux = document.getElementById('ip_specifique_src_deux').value;
        const ip_specifique_dst_deux = document.getElementById('ip_specifique_dst_deux').value;
        const protocol_specifique_deux = document.getElementById('protocol_specifique_deux').value;
        const port_specifique_src_deux = document.getElementById('port_specifique_src_deux').value;
        const port_specifique_dst_deux = document.getElementById('port_specifique_dst_deux').value;

        const chemin_fichier = document.getElementById('fichier_pcap').value;
        const chemin_fichier_deux = document.getElementById('fichier_pcap_deux').value;
        const plage_temps_graphique = document.getElementById('plage_temps_graphique').value;

        const filtres = {
        ip_specifique_src_un: ip_specifique_src_un,
        ip_specifique_dst_un: ip_specifique_dst_un,
        protocol_specifique_un: protocol_specifique_un,
        port_specifique_src_un: port_specifique_src_un,
        port_specifique_dst_un: port_specifique_dst_un,
        ip_specifique_src_deux: ip_specifique_src_deux,
        ip_specifique_dst_deux: ip_specifique_dst_deux,
        protocol_specifique_deux: protocol_specifique_deux,
        port_specifique_src_deux: port_specifique_src_deux,
        port_specifique_dst_deux: port_specifique_dst_deux,

        chemin_fichier: chemin_fichier,
        chemin_fichier_deux: chemin_fichier_deux,
        plage_temps_graphique: plage_temps_graphique,
        mode: mode
        };
        

        const res = await fetch('/genererRapportCsv', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(filtres)
        });

        const data = await res.json();



        if (data.success) {
          document.getElementById('succesCSV').style.display = 'block';
        } else {
          document.getElementById('erreur').textContent = 'Erreur : ' + data.error;
        }

       
        } catch (error) {
            console.error('Erreur:', error);
            document.getElementById('erreur').textContent = 'Erreur: ' + error.message;
      }
    }



    async function generer(typeGraphique, elementPhp) {
      try {
        // Affiche le message de chargement

        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const ip_specifique_src_un = document.getElementById('ip_specifique_src_un').value;
        const ip_specifique_dst_un = document.getElementById('ip_specifique_dst_un').value;
        const protocol_specifique_un = document.getElementById('protocol_specifique_un').value;
        const port_specifique_src_un = document.getElementById('port_specifique_src_un').value;
        const port_specifique_dst_un = document.getElementById('port_specifique_dst_un').value;
        const ip_specifique_src_deux = document.getElementById('ip_specifique_src_deux').value;
        const ip_specifique_dst_deux = document.getElementById('ip_specifique_dst_deux').value;
        const protocol_specifique_deux = document.getElementById('protocol_specifique_deux').value;
        const port_specifique_src_deux = document.getElementById('port_specifique_src_deux').value;
        const port_specifique_dst_deux = document.getElementById('port_specifique_dst_deux').value;

        const chemin_fichier = document.getElementById('fichier_pcap').value;
        const chemin_fichier_deux = document.getElementById('fichier_pcap_deux').value;
        const plage_temps_graphique = document.getElementById('plage_temps_graphique').value;

        const filtres = {
        ip_specifique_src_un: ip_specifique_src_un,
        ip_specifique_dst_un: ip_specifique_dst_un,
        protocol_specifique_un: protocol_specifique_un,
        port_specifique_src_un: port_specifique_src_un,
        port_specifique_dst_un: port_specifique_dst_un,
        ip_specifique_src_deux: ip_specifique_src_deux,
        ip_specifique_dst_deux: ip_specifique_dst_deux,
        protocol_specifique_deux: protocol_specifique_deux,
        port_specifique_src_deux: port_specifique_src_deux,
        port_specifique_dst_deux: port_specifique_dst_deux,
        
        chemin_fichier: chemin_fichier,
        chemin_fichier_deux : chemin_fichier_deux,
        plage_temps_graphique: plage_temps_graphique,
        typeGraphique: typeGraphique,
      };

     

      const res = await fetch('/generer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(filtres)
      });
      

      const data = await res.json();




      if (data.success) {


          const fig = JSON.parse(data.graphique);
          const div = document.getElementById(elementPhp);
          div.style.display = 'block';  // ← réaffiche le div
          Plotly.purge(elementPhp);  // Nettoie le graphique précédent
          Plotly.newPlot(elementPhp, fig.data, fig.layout);
          
      } else {
          document.getElementById('erreur').textContent = 'Erreur : ' + data.error;
      }
      } catch (error) {
        console.log("erreur")
        console.error('Erreur:', error);
        document.getElementById('erreur').textContent = 'Erreur: ' + error.message;
      }
    }

    async function genererDetectionAnomalie(typeAnomalie,elementPhp) {
      console.log(typeAnomalie);
      try {
        // Affiche le message de chargement
        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const ip_specifique_src_un = document.getElementById('ip_specifique_src_un').value;
        const ip_specifique_dst_un = document.getElementById('ip_specifique_dst_un').value;
        const protocol_specifique_un = document.getElementById('protocol_specifique_un').value;
        const port_specifique_src_un = document.getElementById('port_specifique_src_un').value;
        const port_specifique_dst_un = document.getElementById('port_specifique_dst_un').value;
        const ip_specifique_src_deux = document.getElementById('ip_specifique_src_deux').value;
        const ip_specifique_dst_deux = document.getElementById('ip_specifique_dst_deux').value;
        const protocol_specifique_deux = document.getElementById('protocol_specifique_deux').value;
        const port_specifique_src_deux = document.getElementById('port_specifique_src_deux').value;
        const port_specifique_dst_deux = document.getElementById('port_specifique_dst_deux').value;

        const chemin_fichier = document.getElementById('fichier_pcap').value;
        const chemin_fichier_deux = document.getElementById('fichier_pcap_deux').value;
        const plage_temps_graphique = document.getElementById('plage_temps_graphique').value;

        const filtres = {
        ip_specifique_src_un: ip_specifique_src_un,
        ip_specifique_dst_un: ip_specifique_dst_un,
        protocol_specifique_un: protocol_specifique_un,
        port_specifique_src_un: port_specifique_src_un,
        port_specifique_dst_un: port_specifique_dst_un,
        ip_specifique_src_deux: ip_specifique_src_deux,
        ip_specifique_dst_deux: ip_specifique_dst_deux,
        protocol_specifique_deux: protocol_specifique_deux,
        port_specifique_src_deux: port_specifique_src_deux,
        port_specifique_dst_deux: port_specifique_dst_deux,

        chemin_fichier: chemin_fichier,
        chemin_fichier_deux: chemin_fichier_deux,
        plage_temps_graphique: plage_temps_graphique,
        typeAnomalie: typeAnomalie
        };
        

        const res = await fetch('/genererDetectionAnomalie', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(filtres)
        });

        const responseText = await res.text();
        const data = JSON.parse(responseText);

        if (data.success) {
          if (data.anomalies != "aucune anomalie" ){ 
            document.getElementById('detectionAnomalie').classList.remove('cache');
            document.getElementById(elementPhp).textContent = data.anomalies;
            document.getElementById(elementPhp).style.display = 'block';
          }else {
            document.getElementById('detectionAnomalie').classList.add('cache');
          }

        } else {
            document.getElementById('erreur').textContent = 'Erreur : ' + data.error;
        }
        } catch (error) {
          console.error('Erreur:', error);
          document.getElementById('erreur').textContent = 'Erreur: ' + error.message;
        }

    }

    async function genererRapportStatistique(typeStatistique,elementPhp) {
      try {
        // Affiche le message de chargement
        document.getElementById('erreur').textContent = '';

        /// filtres sur les données 
        const ip_specifique_src_un = document.getElementById('ip_specifique_src_un').value;
        const ip_specifique_dst_un = document.getElementById('ip_specifique_dst_un').value;
        const protocol_specifique_un = document.getElementById('protocol_specifique_un').value;
        const port_specifique_src_un = document.getElementById('port_specifique_src_un').value;
        const port_specifique_dst_un = document.getElementById('port_specifique_dst_un').value;
        const ip_specifique_src_deux = document.getElementById('ip_specifique_src_deux').value;
        const ip_specifique_dst_deux = document.getElementById('ip_specifique_dst_deux').value;
        const protocol_specifique_deux = document.getElementById('protocol_specifique_deux').value;
        const port_specifique_src_deux = document.getElementById('port_specifique_src_deux').value;
        const port_specifique_dst_deux = document.getElementById('port_specifique_dst_deux').value;

        const chemin_fichier_deux = document.getElementById('fichier_pcap_deux').value;
        const chemin_fichier = document.getElementById('fichier_pcap').value;
        const plage_temps_graphique = document.getElementById('plage_temps_graphique').value;

        const filtres = {
        ip_specifique_src_un: ip_specifique_src_un,
        ip_specifique_dst_un: ip_specifique_dst_un,
        protocol_specifique_un: protocol_specifique_un,
        port_specifique_src_un: port_specifique_src_un,
        port_specifique_dst_un: port_specifique_dst_un,
        ip_specifique_src_deux: ip_specifique_src_deux,
        ip_specifique_dst_deux: ip_specifique_dst_deux,
        protocol_specifique_deux: protocol_specifique_deux,
        port_specifique_src_deux: port_specifique_src_deux,
        port_specifique_dst_deux: port_specifique_dst_deux,

        chemin_fichier: chemin_fichier,
        chemin_fichier_deux: chemin_fichier_deux,
        plage_temps_graphique: plage_temps_graphique,
        typeStatistique: typeStatistique
        };
        

        const res = await fetch('/genererRapportStatistique', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(filtres)
        });

        const responseText = await res.text();
        const data = JSON.parse(responseText);

        
        if (data.success) {
          document.getElementById(elementPhp).textContent = data.statistique;
          document.getElementById(elementPhp).style.display = 'block';

        } else {
            document.getElementById('erreur').textContent = 'Erreur : ' + data.error;
        }
        } catch (error) {
          console.error('Erreur:', error);
          document.getElementById('erreur').textContent = 'Erreur: ' + error.message;
        }
    }

    async function genererRapportAvecDeuxFichiers(){
      try {
        // Affiche le message de chargement
        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const ip_specifique_src_un = document.getElementById('ip_specifique_src_un').value;
        const ip_specifique_dst_un = document.getElementById('ip_specifique_dst_un').value;
        const protocol_specifique_un = document.getElementById('protocol_specifique_un').value;
        const port_specifique_src_un = document.getElementById('port_specifique_src_un').value;
        const port_specifique_dst_un = document.getElementById('port_specifique_dst_un').value;
        const ip_specifique_src_deux = document.getElementById('ip_specifique_src_deux').value;
        const ip_specifique_dst_deux = document.getElementById('ip_specifique_dst_deux').value;
        const protocol_specifique_deux = document.getElementById('protocol_specifique_deux').value;
        const port_specifique_src_deux = document.getElementById('port_specifique_src_deux').value;
        const port_specifique_dst_deux = document.getElementById('port_specifique_dst_deux').value;

        const chemin_fichier = document.getElementById('fichier_pcap').value;
        const chemin_fichier_deux = document.getElementById('fichier_pcap_deux').value;
        const plage_temps_graphique = document.getElementById('plage_temps_graphique').value;

        const filtres = {
          ip_specifique_src_un: ip_specifique_src_un,
          ip_specifique_dst_un: ip_specifique_dst_un,
          protocol_specifique_un: protocol_specifique_un,
          port_specifique_src_un: port_specifique_src_un,
          port_specifique_dst_un: port_specifique_dst_un,
          ip_specifique_src_deux: ip_specifique_src_deux,
          ip_specifique_dst_deux: ip_specifique_dst_deux,
          protocol_specifique_deux: protocol_specifique_deux,
          port_specifique_src_deux: port_specifique_src_deux,
          port_specifique_dst_deux: port_specifique_dst_deux,

          chemin_fichier: chemin_fichier,
          chemin_fichier_deux: chemin_fichier_deux,
          plage_temps_graphique: plage_temps_graphique,
        };

        const res = await fetch('/genererRapportAvecDeuxFichiers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(filtres)
        });

        const responseText = await res.text();
        const data = JSON.parse(responseText);

        if (data.success) {
          // Traitez les données renvoyées par le serveur
          console.log(data.rapport);
        } else {
            document.getElementById('erreur').textContent = 'Erreur : ' + data.error;
        }
        } catch (error) {
          console.error('Erreur:', error);
          document.getElementById('erreur').textContent = 'Erreur: ' + error.message;
        }


    }

    async function regenererGraphiques(){
      
        document.getElementById('caseGraphiqueHistogrammeIntra').style.display = 'none'
        document.getElementById('caseGraphiqueCumulatifIntra').style.display = 'none'
        document.getElementById('caseGraphiqueDensiteIntra').style.display = 'none'
        document.getElementById('caseGraphiqueCumulatifeInter').style.display = 'none'
        document.getElementById('caseGraphiqueDensiteInter').style.display = 'none'
        document.getElementById('caseGraphiqueRepartitionInterFull').style.display = 'none'
        document.getElementById('caseHistogrammeDensiteTaille').style.display = 'none'
        document.getElementById('caseDebitTaille').style.display = 'none'
        document.getElementById("texteScanPort").textContent = ""
        document.getElementById("texteReemissionPaquet").textContent = ""

        icon = document.getElementById('chargementIcon');
        texte = document.getElementById('chargementTexte');
        alerteAnomalie = document.getElementById('detectionAnomalie');
        seconde_fichier_pcap = document.getElementById('fichier_pcap_deux').value;
        alerteAnomalie.classList.add('cache'); 
        icon.classList.remove('cache');
        texte.classList.remove('cache');
        texte.textContent = "Chargement... du fichier PCAP"

        if (seconde_fichier_pcap != null && seconde_fichier_pcap !== "") {
          await genererRapportAvecDeuxFichiers()
          texte.textContent = "Chargement... des fichiers PCAP"
        }

        await generer('CoucheDeux',"graphiqueEtherType");
        texte.textContent = "Chargement... du graphique CoucheTrois"
        await generer('CoucheTrois',"graphiqueCoucheTrois");
        texte.textContent = "Chargement... du graphique CoucheQuatre"
        await generer('CoucheQuatre',"graphiqueCoucheQuatre");
        texte.textContent = "Chargement... du graphique graphiqueServiceSource"
        await generer('CoucheServiceSource',"graphiqueServiceSource");
        texte.textContent = "Chargement... du graphique graphiqueServiceDestination"
        await generer('CoucheServiceDestination',"graphiqueServiceDestination");
        texte.textContent = "Chargement... de la détection d'anomalie (Scan de port)"
        await genererDetectionAnomalie('scanPort','texteScanPort')
        texte.textContent = "Chargement... de la détection d'anomalie (Réemission TCP)"
        await genererDetectionAnomalie('reemissionTcp','texteReemissionPaquet')
        texte.textContent = "Chargement... de la liste de flux"
        await genererRapportStatistique('flux',"conteneurFlux");
        texte.textContent = "Chargement... de l'ip src la plus active"
        await genererRapportStatistique('ipPlusActiveSrc',"topIpSrc");
        texte.textContent = "Chargement... de l'ip dst la plus active"
        await genererRapportStatistique('ipPlusActiveDst',"topIpDst");
        texte.textContent = "Chargement... du nombre de paquet"
        await genererRapportStatistique('nbPaquet',"afficherNombrePaquet");

        icon.classList.add('cache');
        texte.classList.add('cache');
    }


// pour recadrer les graphiques dans le carousel 
document.addEventListener('DOMContentLoaded', function (){
  document.getElementById('carouselGraphiques').addEventListener('click', function (e){
    const ids = [
      'graphiqueEtherType',
      'graphiqueCoucheTrois',
      'graphiqueCoucheQuatre',
      'graphiqueServiceSource',
      'graphiqueServiceDestination'
    ];

    setTimeout(() => {
    ids.forEach(id => Plotly.relayout(id, { autosize: true,autosize: true }));
    },400)
  });
});

//pour la pop up des anomalies 

function openAnomaliePopUp(){
  document.getElementById('overlay').style.display = 'flex';
}

function closeAnomaliesPopUp(){
  document.getElementById('overlay').style.display = 'none';
}

document.addEventListener('DOMContentLoaded', function (){
  document.getElementById('overlay').style.display = 'none';

  // Fermer avec Échap
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAnomaliesPopUp();
  });

  // Fermer au clic sur l'overlay
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeAnomaliesPopUp();
  });
});




