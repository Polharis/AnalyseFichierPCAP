# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
# Ajouter le chemin vers votre code source
import os, sys


# Thème (optionnel)
html_theme = 'sphinx_rtd_theme'

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'AnalyseFichierPCAP'
copyright = '2026, Robin'
author = 'Robin'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

sys.path.insert(0, os.path.abspath('../scriptPy'))
sys.path.insert(0, os.path.abspath('../scriptPy/filtrageDonnee'))
sys.path.insert(0, os.path.abspath('../scriptPy/LectureDonne'))
sys.path.insert(0, os.path.abspath('../scriptPy/graphiques'))
sys.path.insert(0, os.path.abspath('../scriptPy/statistiques'))

# Extensions utiles
extensions = [
    'sphinx.ext.autodoc',    # génère doc depuis docstrings
    'sphinx.ext.viewcode',   # liens vers le code source
    'sphinx.ext.napoleon',   # support Google/NumPy docstrings
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

language = 'fr'

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
