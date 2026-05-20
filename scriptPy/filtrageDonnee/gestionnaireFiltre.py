class GestionnaireFiltres:
    def __init__(self):
        self._filtres = {}
        self._id = id(self)  # Pour tracer les instances

    def appliquer(self, params):
        self._filtres.clear()
        self._filtres.update(params)

    def get(self):
        return self._filtres.copy()

#Variable globale pour stocker les filtres à appliquer
gestionnaire = GestionnaireFiltres()
