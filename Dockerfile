# Image de base Python
FROM python:3.11-slim

# Répertoire de travail dans le conteneur
WORKDIR /app

# Copier et installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le projet
COPY . .

# Exposer le port Flask
EXPOSE 5000

# Lancer l'application
CMD ["python", "app.py"]