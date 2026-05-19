# AnalyseFichierPCAP


# Description rapide

Application python analysant la composition d'un fichier PCAP ou PCAPng.
Une interface web permet une meilleure prise en main de l'application

## Installation

Pour démarrer le serveur développement Flask :
 - Ce placer dans à la racine du projet (AnalyseFichierPCAP)
 - Si dans un environnement virtuel, l'activer (source venv/bin/activate)
 - lancer app.py (python "app.py")


## Utilisation rapide (exemple concret)

Une fois le serveur flask lancé, il suffit d'y accéder depuis un navigateur internet, ici : 
http://localhost:5000/

## Structure du projet

Le projet possède deux parties bien distinct.
Premièrement il y a tous les composant permettant de faire tourner l'interface web : 
 - index.php
 - style.css
 -script.jsphp

Ensuite app.py est le composant flask permettant de relier l'interface web au code python

La deuxième partie est donc le code python scriptPy, qui est composé de plusieurs parties pour
extraire et traiter les informations issues des fichier PCAP : 
 - LectureDonne, qui est le composant principal de l'application.
    Il permet de parser un fichier PCAP avec lectureDonneFichierUnique puis de créer un structure de 
    donnée personalisé dans triDeDonnees.
    LectureDonne est aussi composé de creationCSV pour faire des rapport sous la forme de CSV.
    Ainsi que detectionAnomalie qui est le fichier qui envoie les informations de comportement
    anormaux à la vue lorsqu'il y en a.
  -ListeFiltre, qui contient tout les composant pour appliquer les filtres pris en compte dans l'interface web
  -statistiques, permet de générer des dictionnaire est string en analysant la structure de donnée obtenues avec 
  trieDeDonnees
  -graphiques, ensemble d'outils de création de graphique se reposant sur les résultat obtenues avec les outils de 
  statistiques

  Le main.py sert à faire le lien entre app.py et l'ensemble de l'application python

## Lien vers la doc Sphinx complète

Pour accéder à la documentation sphinx, il faut : 
 - se placer dans le répertoire docs et avoir l'environnement d'activer si il y en a un
 - générer la doc html : make html
 - accéder à la doc depuis un navigateur en tapant sur la console : xdg-open _build/html/index.html

# Contributeur 

  Christol Robin robin.christol@iut-rodez.fr Robin-Christol(Polharis)
