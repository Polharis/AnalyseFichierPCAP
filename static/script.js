    est_formulaire_filtre_ouvert = false;
    est_options_graphique_ouvert = false;
    est_options_statistique_ouvert = false;
    est_options_rapport_CSV_ouvert = false;

    function changer_etat_formulaire(){
        if (est_formulaire_filtre_ouvert) {
            fermerFormulaire();
           
        } else {
            cacherToutElement()
            afficherFormulaire();
            
        }
    }

    function changer_etat_option_graphique(){
        if (est_options_graphique_ouvert) {
            cacherOptionGraphique();
            

        } else {
            cacherToutElement()
            afficherOptionGraphique();
            
        }
    }

    function changer_etat_option_statistique(){
        
        if (est_options_statistique_ouvert) {
            cacherOptionStatistique();
            
        } else {
            cacherToutElement()
            afficherOptionStatistique();
            
        }
    }

    function changer_etat_option_rapport_CSV() {
        if (est_options_rapport_CSV_ouvert) {
            cacherOptionRapportCSV();
            
        } else {
            cacherToutElement()
            afficherOptionRapportCSV();
            
        }
    }
    

    function afficherFormulaire() {
      document.getElementById('casePourFiltre').style.display = 'block';
      document.getElementById('bouton_options').textContent = 'Fermer les options';
      est_formulaire_filtre_ouvert = true;
    }

    function fermerFormulaire() {
      document.getElementById('casePourFiltre').style.display = 'none';
      document.getElementById('bouton_options').textContent = 'Ouvrir les options';
      est_formulaire_filtre_ouvert = false;
    }

    function afficherOptionGraphique() {
        document.getElementById('casePourGraphique').style.display = 'block';
        document.getElementById('buttonGraphics').textContent = 'Fermer les options graphiques';
        est_options_graphique_ouvert = true;
    }

    function cacherOptionGraphique() {
        document.getElementById('casePourGraphique').style.display = 'none';
        document.getElementById('buttonGraphics').textContent = 'Ouvrir les options graphiques';
        document.getElementById('graphique').style.display = 'none';
        est_options_graphique_ouvert = false;
    }

    function afficherOptionStatistique() {
        document.getElementById('casePourStatstique').style.display = 'block';
        document.getElementById('buttonStatistics').textContent = 'Fermer les options statistiques';
        est_options_statistique_ouvert = true;
    }

    function cacherOptionStatistique() {
        document.getElementById('casePourStatstique').style.display = 'none';
        document.getElementById('buttonStatistics').textContent = 'Ouvrir les options statistiques';
        document.getElementById('statistique').style.display = 'none';
        est_options_statistique_ouvert = false;
    }

    function afficherOptionRapportCSV() {
        document.getElementById('casePourRapportCSV').style.display = 'block';
        document.getElementById('genererRapportCsv').textContent = 'Fermer les options rapport CSV';
        est_options_rapport_CSV_ouvert = true;
    }

    function cacherOptionRapportCSV() {
        document.getElementById('casePourRapportCSV').style.display = 'none';
        document.getElementById('genererRapportCsv').textContent = 'Générer rapport CSV';
        document.getElementById('succesCSV').style.display = 'none';
        est_options_rapport_CSV_ouvert = false;
    }

    function cacherToutElement() {
      fermerFormulaire();
      cacherOptionGraphique();
      cacherOptionStatistique();
      cacherOptionRapportCSV();
      document.getElementById('erreur').textContent = '';
    }


    async function genererRapportCsv() {
      try {
        // Affiche le message de chargement
        document.getElementById('chargement').style.display = 'block';
        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const proto_filtre = document.querySelector('input[name="proto_filtre"]:checked').value;
        const ip_specifique = document.getElementById('ip_specifique').value;
        const protocol_specifique = document.getElementById('protocol_specifique').value;
        const port_specifique = document.getElementById('port_specifique').value;
        const chemin_fichier = document.getElementById('fichier_pcap').value;

        const filtres = {
        proto_filtre: proto_filtre,
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



    async function generer(typeGraphique) {
      try {
        // Affiche le message de chargement
        document.getElementById('chargement').style.display = 'block';
        document.getElementById('graphique').style.display = 'none';
        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const proto_filtre = document.querySelector('input[name="proto_filtre"]:checked').value;
        const ip_specifique = document.getElementById('ip_specifique').value;
        const protocol_specifique = document.getElementById('protocol_specifique').value;
        const port_specifique = document.getElementById('port_specifique').value;
        const chemin_fichier = document.getElementById('fichier_pcap').value;
        const plage_temps_graphique = document.getElementById('plage_temps_graphique').value;
        

      const filtres = {
        proto_filtre: proto_filtre,
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



      document.getElementById('chargement').style.display = 'none';

      if (data.success) {
          const fig = JSON.parse(data.graphique);
          const div = document.getElementById('graphique');
          div.style.display = 'block';  // ← réaffiche le div
          Plotly.newPlot('graphique', fig.data, fig.layout);
      } else {
          document.getElementById('erreur').textContent = 'Erreur : ' + data.error;
      }
      } catch (error) {
        console.error('Erreur:', error);
        document.getElementById('erreur').textContent = 'Erreur: ' + error.message;
        document.getElementById('chargement').style.display = 'none';
      }
    }

    async function genererRapportStatistique(typeStatistique) {
      try {
        // Affiche le message de chargement
        document.getElementById('chargement').style.display = 'block';
        document.getElementById('erreur').textContent = '';

        // filtres sur les données 
        const proto_filtre = document.querySelector('input[name="proto_filtre"]:checked').value;
        const ip_specifique = document.getElementById('ip_specifique').value;
        const protocol_specifique = document.getElementById('protocol_specifique').value;
        const port_specifique = document.getElementById('port_specifique').value;
        const chemin_fichier = document.getElementById('fichier_pcap').value;

        const filtres = {
        proto_filtre: proto_filtre,
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

        document.getElementById('chargement').style.display = 'none';
        
        if (data.success) {
          document.getElementById('statistique').textContent = data.statistique;
          document.getElementById('statistique').style.display = 'block';
        } else {
            document.getElementById('erreur').textContent = 'Erreur : ' + data.error;
        }
        } catch (error) {
          console.error('Erreur:', error);
          document.getElementById('erreur').textContent = 'Erreur: ' + error.message;
          document.getElementById('chargement').style.display = 'none';
        }
    }