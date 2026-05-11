
document.addEventListener("DOMContentLoaded", async function() {
    document.getElementById('afficherGraphiqueHistogrammeIntra').style.display = 'none'
    document.getElementById('afficherGraphiqueCumulatifeIntra').style.display = 'none'
    document.getElementById('afficherGraphiqueCumulatifeInter').style.display = 'none'

    icon = document.getElementById('chargementIcon')
    texte = document.getElementById('chargementTexte')
    icon.classList.remove('cache');
    texte.classList.remove('cache');

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
    texte.textContent = "Chargement... de la liste de flux"
    await genererRapportStatistique('flux',"conteneurFlux");
    texte.textContent = "Chargement... du nombre de paquet"
    await genererRapportStatistique('nbPaquet',"afficherNombrePaquet");

    icon.classList.add('cache');
    texte.classList.add('cache');
});

    async function appliquerGraphs(){

        await regenererGraphiques();
        histogrammeIntra = document.getElementById('graphiqueHistogrammeIntra');
        cumulatifIntra = document.getElementById('graphiqueCumulatifIntra');
        cumulatifInter = document.getElementById('graphiqueCumulatifInter');

        icon = document.getElementById('chargementIcon')
        texte = document.getElementById('chargementTexte')

        icon.classList.remove('cache');
        texte.classList.remove('cache');

        if(histogrammeIntra.checked){
            texte.textContent = "Chargement... du graphique HistogrammeIntra"
            await generer('IntraEspacement',"afficherGraphiqueHistogrammeIntra");
        }else{
            document.getElementById('afficherGraphiqueHistogrammeIntra').style.display = 'none'
        }
        if(cumulatifIntra.checked){
            texte.textContent = "Chargement... du graphique répartition cumulative intra"
            await generer('IntraEspacementRepartition',"afficherGraphiqueCumulatifeIntra");
        }else{
            document.getElementById('afficherGraphiqueCumulatifeIntra').style.display = 'none'
        }
        if(cumulatifInter.checked){
            texte.textContent = "Chargement... du graphique répartition cumulative inter"
            await generer('InterEspacementRepartition',"afficherGraphiqueCumulatifeInter");
        }else{
            document.getElementById('afficherGraphiqueCumulatifeInter').style.display = 'none'
        }

        icon.classList.add('cache');
        texte.classList.add('cache');
    } 


    async function genererRapportCsv() {
      try {
        // Affiche le message de chargement
        document.getElementById('chargement').style.display = 'block';
        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const ip_specifique = document.getElementById('ip_specifique').value;
        const protocol_specifique = document.getElementById('protocol_specifique').value;
        const port_specifique = document.getElementById('port_specifique').value;
        const chemin_fichier = document.getElementById('fichier_pcap').value;

        const filtres = {
        ip_specifique: ip_specifique,
        protocol_specifique: protocol_specifique,
        port_specifique: port_specifique,
        chemin_fichier: chemin_fichier
        };
        

        const res = await fetch('/genererRapportCsv', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(filtres)
        });

        const data = await res.json();



        document.getElementById('chargement').style.display = 'none';
        if (data.success) {
          document.getElementById('succesCSV').style.display = 'block';
        } else {
          document.getElementById('erreur').textContent = 'Erreur : ' + data.error;
        }

       
        } catch (error) {
            console.error('Erreur:', error);
            document.getElementById('erreur').textContent = 'Erreur: ' + error.message;
            document.getElementById('chargement').style.display = 'none';
      }
    }



    async function generer(typeGraphique, elementPhp) {
      try {
        // Affiche le message de chargement

        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const ip_specifique = document.getElementById('ip_specifique').value;
        const protocol_specifique = document.getElementById('protocol_specifique').value;
        const port_specifique = document.getElementById('port_specifique').value;
        const chemin_fichier = document.getElementById('fichier_pcap').value;
        const plage_temps_graphique = document.getElementById('plage_temps_graphique').value;
        

      const filtres = {
        ip_specifique: ip_specifique,
        protocol_specifique: protocol_specifique,
        port_specifique: port_specifique,
        typeGraphique: typeGraphique,
        chemin_fichier: chemin_fichier,
        plage_temps_graphique: plage_temps_graphique
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

    async function genererRapportStatistique(typeStatistique,elementPhp) {
      try {
        // Affiche le message de chargement
        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const ip_specifique = document.getElementById('ip_specifique').value;
        const protocol_specifique = document.getElementById('protocol_specifique').value;
        const port_specifique = document.getElementById('port_specifique').value;
        const chemin_fichier = document.getElementById('fichier_pcap').value;

        const filtres = {
        ip_specifique: ip_specifique,
        protocol_specifique: protocol_specifique,
        port_specifique: port_specifique,
        chemin_fichier: chemin_fichier,
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

    async function regenererGraphiques(){
        document.getElementById('afficherGraphiqueHistogrammeIntra').style.display = 'none'
        document.getElementById('afficherGraphiqueCumulatifeIntra').style.display = 'none'
        document.getElementById('afficherGraphiqueCumulatifeInter').style.display = 'none'

        icon = document.getElementById('chargementIcon')
        texte = document.getElementById('chargementTexte')
        icon.classList.remove('cache');
        texte.classList.remove('cache');
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
        texte.textContent = "Chargement... de la liste de flux"
        await genererRapportStatistique('flux',"conteneurFlux");
        texte.textContent = "Chargement... du nombre de paquet"
        await genererRapportStatistique('nbPaquet',"afficherNombrePaquet");

        icon.classList.add('cache');
        texte.classList.add('cache');
    }


// pour recadrer les graphiques dans le carousel 
document.addEventListener('DOMContentLoaded', function (){
  document.getElementById('carouselGraphiques').addEventListener('click', function (e){
    console.log("ok");
    const ids = [
      'graphiqueEtherType',
      'graphiqueCoucheTrois',
      'graphiqueCoucheQuatre',
      'graphiqueServiceSource',
      'graphiqueServiceDestination'
    ];

    setTimeout(() => {
    ids.forEach(id => Plotly.relayout(id, { autosize: true }));
    },400)
  });
});