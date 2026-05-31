from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
from bson import ObjectId
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="SANI-FÉRÉ V2 API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
SECRET_KEY = os.getenv("SECRET_KEY", "sanifere-secret-2026")
DB_NAME = os.getenv("DB_NAME", "sanifere")
# Numéro Orange Money marchand affiché au client au moment de payer.
# ⚠️ À définir sur Railway (variable ORANGE_MONEY_NUMERO) — ne pas le mettre en dur ici.
ORANGE_MONEY_NUMERO = os.getenv("ORANGE_MONEY_NUMERO", "À CONFIGURER")
ORANGE_MONEY_NOM = os.getenv("ORANGE_MONEY_NOM", "SANI-FERE")

client = MongoClient(MONGO_URL)
db = client[DB_NAME]

security = HTTPBearer(auto_error=False)

# ─── Helpers ───────────────────────────────────────────
def serialize(obj):
    if obj is None:
        return None
    if isinstance(obj, list):
        return [serialize(o) for o in obj]
    if isinstance(obj, dict):
        obj = dict(obj)
        if "_id" in obj:
            obj["id"] = str(obj.pop("_id"))
        for k, v in obj.items():
            if isinstance(v, ObjectId):
                obj[k] = str(v)
            elif isinstance(v, datetime):
                obj[k] = v.isoformat()
        return obj
    return obj

def create_token(user_id: str, role: str = "acheteur"):
    payload = {"sub": user_id, "role": role, "exp": datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None

def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = get_current_user(credentials)
    if not user:
        raise HTTPException(401, "Non authentifié")
    return user

def require_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = get_current_user(credentials)
    if not user or user.get("role") != "admin":
        raise HTTPException(403, "Réservé à l'administrateur")
    return user

def prochaine_cloture():
    """Calcule la prochaine expédition groupée (le 25 du mois)."""
    t = datetime.utcnow()
    y, m = t.year, t.month
    if t.day > 25:
        m += 1
        if m > 12:
            m, y = 1, y + 1
    mois = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet",
            "août", "septembre", "octobre", "novembre", "décembre"][m - 1]
    d = datetime(y, m, 25)
    jours = (d.date() - t.date()).days
    return {"date": d.date().isoformat(), "label": f"25 {mois}", "jours_restants": max(0, jours)}

# ─── Modèles ───────────────────────────────────────────
class InscriptionUser(BaseModel):
    nom: str
    prenom: str
    email: str
    telephone: str
    mot_de_passe: str
    ville: Optional[str] = "Bamako"

class ConnexionUser(BaseModel):
    email: str
    mot_de_passe: str

class ProduitCreate(BaseModel):
    nom: str
    description: str = ""
    prix: float                      # prix de l'article en FCFA
    frais_livraison: float = 0       # frais de livraison Mali en FCFA (par article)
    categorie: str                   # naissance, bebe, fille, garcon, chaussures, accessoires
    vitrine: str = "okaidi"          # okaidi, obaibi (= la marque)
    marque: Optional[str] = None     # libellé affiché (OKAÏDI, OBAÏBI…)
    images: List[str] = []
    taille: Optional[str] = None
    prix_barre: Optional[float] = None  # ancien prix (pour afficher une promo)

class ProduitUpdate(BaseModel):
    nom: Optional[str] = None
    description: Optional[str] = None
    prix: Optional[float] = None
    frais_livraison: Optional[float] = None
    categorie: Optional[str] = None
    vitrine: Optional[str] = None
    marque: Optional[str] = None
    images: Optional[List[str]] = None
    taille: Optional[str] = None
    prix_barre: Optional[float] = None
    disponible: Optional[bool] = None

class LigneCommande(BaseModel):
    produit_id: str
    quantite: int = 1

class CommandeCreate(BaseModel):
    articles: List[LigneCommande]            # le panier complet
    nom_client: str
    telephone_acheteur: str
    adresse_livraison: str                   # point de repère / description
    ville: Optional[str] = "Bamako"
    mode_paiement: str = "orange_money"

# ─── Root ───────────────────────────────────────────────
@app.get("/")
def root():
    return {"message": "SANI-FÉRÉ V2 API", "status": "ok", "prochaine_cloture": prochaine_cloture()}

# ─── AUTH (acheteurs) ───────────────────────────────────
@app.post("/api/auth/inscription")
def inscription(data: InscriptionUser):
    if db.users.find_one({"email": data.email}):
        raise HTTPException(400, "Email déjà utilisé")
    if db.users.find_one({"telephone": data.telephone}):
        raise HTTPException(400, "Téléphone déjà utilisé")
    hashed = bcrypt.hashpw(data.mot_de_passe.encode(), bcrypt.gensalt()).decode()
    user = {
        "nom": data.nom, "prenom": data.prenom, "email": data.email,
        "telephone": data.telephone, "mot_de_passe": hashed,
        "role": "acheteur", "ville": data.ville,
        "date_inscription": datetime.utcnow(), "actif": True,
    }
    result = db.users.insert_one(user)
    token = create_token(str(result.inserted_id), "acheteur")
    return {"token": token, "role": "acheteur", "message": "Inscription réussie"}

@app.post("/api/auth/connexion")
def connexion(data: ConnexionUser):
    user = db.users.find_one({"email": data.email})
    if not user or not bcrypt.checkpw(data.mot_de_passe.encode(), user["mot_de_passe"].encode()):
        raise HTTPException(401, "Email ou mot de passe incorrect")
    token = create_token(str(user["_id"]), user.get("role", "acheteur"))
    return {"token": token, "role": user.get("role"),
            "user": serialize({k: v for k, v in user.items() if k != "mot_de_passe"})}

@app.get("/api/auth/profil")
def mon_profil(user=Depends(require_auth)):
    u = db.users.find_one({"_id": ObjectId(user["sub"])})
    if not u:
        raise HTTPException(404, "Utilisateur non trouvé")
    u.pop("mot_de_passe", None)
    return serialize(u)

# ─── VITRINES & CATÉGORIES ──────────────────────────────
@app.get("/api/vitrines")
def lister_vitrines():
    # Architecture multi-marques : ajoute une enseigne ici quand tu en ouvres une.
    return [
        {"id": "okaidi", "nom": "OKAÏDI", "actif": True},
        {"id": "obaibi", "nom": "OBAÏBI", "actif": True},
    ]

@app.get("/api/categories")
def lister_categories():
    return [
        {"slug": "naissance",   "nom": "Naissance",   "emoji": "🍼"},
        {"slug": "bebe",        "nom": "Bébé 0-2 ans", "emoji": "👶"},
        {"slug": "fille",       "nom": "Fille",        "emoji": "👧"},
        {"slug": "garcon",      "nom": "Garçon",       "emoji": "👦"},
        {"slug": "chaussures",  "nom": "Chaussures",   "emoji": "👟"},
        {"slug": "accessoires", "nom": "Accessoires",  "emoji": "🧢"},
    ]

# ─── PRODUITS ───────────────────────────────────────────
@app.get("/api/produits")
def lister_produits(
    page: int = 1, limit: int = 40,
    vitrine: Optional[str] = None,
    categorie: Optional[str] = None,
    q: Optional[str] = None,
    min_prix: Optional[float] = None,
    max_prix: Optional[float] = None,
):
    query = {"disponible": True}
    if vitrine:
        query["vitrine"] = vitrine
    if categorie:
        query["categorie"] = categorie
    if q:
        query["$or"] = [
            {"nom": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"marque": {"$regex": q, "$options": "i"}},
        ]
    if min_prix or max_prix:
        query["prix"] = {}
        if min_prix:
            query["prix"]["$gte"] = min_prix
        if max_prix:
            query["prix"]["$lte"] = max_prix

    skip = (page - 1) * limit
    total = db.produits.count_documents(query)
    produits = list(db.produits.find(query).sort("date_creation", -1).skip(skip).limit(limit))
    return {"total": total, "page": page, "limit": limit, "produits": serialize(produits)}

@app.get("/api/produits/{produit_id}")
def get_produit(produit_id: str):
    try:
        p = db.produits.find_one({"_id": ObjectId(produit_id)})
    except Exception:
        raise HTTPException(400, "ID invalide")
    if not p:
        raise HTTPException(404, "Produit non trouvé")
    db.produits.update_one({"_id": p["_id"]}, {"$inc": {"nb_vues": 1}})
    return serialize(p)

# Création / modif / suppression : ADMIN uniquement (logique vitrine, pas de vendeurs)
@app.post("/api/produits")
def creer_produit(data: ProduitCreate, user=Depends(require_admin)):
    produit = {
        **data.dict(),
        "disponible": True,
        "nb_vues": 0,
        "nb_favoris": 0,
        "date_creation": datetime.utcnow(),
    }
    if not produit.get("marque"):
        produit["marque"] = data.vitrine.upper()
    result = db.produits.insert_one(produit)
    return {"id": str(result.inserted_id), "message": "Produit ajouté au catalogue"}

@app.put("/api/produits/{produit_id}")
def modifier_produit(produit_id: str, data: ProduitUpdate, user=Depends(require_admin)):
    try:
        p = db.produits.find_one({"_id": ObjectId(produit_id)})
    except Exception:
        raise HTTPException(400, "ID invalide")
    if not p:
        raise HTTPException(404, "Produit non trouvé")
    update = {k: v for k, v in data.dict().items() if v is not None}
    db.produits.update_one({"_id": ObjectId(produit_id)}, {"$set": update})
    return {"message": "Produit mis à jour"}

@app.delete("/api/produits/{produit_id}")
def supprimer_produit(produit_id: str, user=Depends(require_admin)):
    try:
        db.produits.delete_one({"_id": ObjectId(produit_id)})
    except Exception:
        raise HTTPException(400, "ID invalide")
    return {"message": "Produit supprimé"}

# ─── COMMANDES (panier complet → expédition du 25) ──────
@app.post("/api/commandes")
def creer_commande(data: CommandeCreate, credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not data.articles:
        raise HTTPException(400, "Panier vide")

    user = get_current_user(credentials)  # auth optionnelle : invité possible
    lignes, total_articles, total_livraison = [], 0, 0

    for item in data.articles:
        try:
            p = db.produits.find_one({"_id": ObjectId(item.produit_id)})
        except Exception:
            raise HTTPException(400, f"ID produit invalide: {item.produit_id}")
        if not p or not p.get("disponible"):
            raise HTTPException(400, f"Produit indisponible: {item.produit_id}")
        sous_total = p["prix"] * item.quantite
        livraison = p.get("frais_livraison", 0) * item.quantite
        total_articles += sous_total
        total_livraison += livraison
        lignes.append({
            "produit_id": p["_id"], "nom": p["nom"], "vitrine": p.get("vitrine"),
            "prix": p["prix"], "frais_livraison": p.get("frais_livraison", 0),
            "quantite": item.quantite, "sous_total": sous_total + livraison,
        })

    cloture = prochaine_cloture()
    commande = {
        "articles": lignes,
        "nom_client": data.nom_client,
        "telephone_acheteur": data.telephone_acheteur,
        "adresse_livraison": data.adresse_livraison,
        "ville": data.ville,
        "mode_paiement": data.mode_paiement,
        "total_articles": total_articles,
        "total_livraison": total_livraison,
        "prix_total": total_articles + total_livraison,
        "cloture_prevue": cloture["date"],
        "statut": "en_attente_paiement",
        "acheteur_id": ObjectId(user["sub"]) if user else None,
        "date_commande": datetime.utcnow(),
    }
    result = db.commandes.insert_one(commande)
    return {
        "id": str(result.inserted_id),
        "prix_total": commande["prix_total"],
        "total_articles": total_articles,
        "total_livraison": total_livraison,
        "expedition": cloture,
        "paiement": {
            "operateur": "Orange Money",
            "numero": ORANGE_MONEY_NUMERO,
            "nom": ORANGE_MONEY_NOM,
            "instruction": f"Envoyez {total_articles + total_livraison} FCFA au {ORANGE_MONEY_NUMERO} ({ORANGE_MONEY_NOM}), puis indiquez la référence de commande.",
            "reference": str(result.inserted_id)[-6:].upper(),
        },
        "message": "Commande enregistrée. Réglez en Orange Money pour valider.",
    }

@app.get("/api/mes-commandes")
def mes_commandes(user=Depends(require_auth)):
    commandes = list(db.commandes.find({"acheteur_id": ObjectId(user["sub"])}).sort("date_commande", -1))
    return serialize(commandes)

# ─── FAVORIS ────────────────────────────────────────────
@app.post("/api/favoris/{produit_id}")
def toggle_favori(produit_id: str, user=Depends(require_auth)):
    uid = ObjectId(user["sub"])
    try:
        pid = ObjectId(produit_id)
    except Exception:
        raise HTTPException(400, "ID invalide")
    existing = db.favoris.find_one({"user_id": uid, "produit_id": pid})
    if existing:
        db.favoris.delete_one({"_id": existing["_id"]})
        db.produits.update_one({"_id": pid}, {"$inc": {"nb_favoris": -1}})
        return {"favori": False}
    db.favoris.insert_one({"user_id": uid, "produit_id": pid, "date": datetime.utcnow()})
    db.produits.update_one({"_id": pid}, {"$inc": {"nb_favoris": 1}})
    return {"favori": True}

@app.get("/api/mes-favoris")
def mes_favoris(user=Depends(require_auth)):
    favs = list(db.favoris.find({"user_id": ObjectId(user["sub"])}))
    produits = []
    for f in favs:
        p = db.produits.find_one({"_id": f["produit_id"]})
        if p:
            produits.append(serialize(p))
    return produits

# ─── ADMIN ──────────────────────────────────────────────
@app.get("/api/admin/stats")
def admin_stats(user=Depends(require_admin)):
    return {
        "acheteurs": db.users.count_documents({"role": "acheteur"}),
        "produits": db.produits.count_documents({}),
        "commandes": db.commandes.count_documents({}),
        "commandes_en_attente": db.commandes.count_documents({"statut": "en_attente_paiement"}),
        "prochaine_cloture": prochaine_cloture(),
    }

@app.get("/api/admin/commandes")
def admin_commandes(user=Depends(require_admin)):
    commandes = list(db.commandes.find({}).sort("date_commande", -1))
    return serialize(commandes)

# ─── PURGE des anciens produits marketplace ────────────
@app.delete("/api/admin/purge-anciens")
def purge_anciens(user=Depends(require_admin)):
    """Supprime uniquement les anciens produits (sans champ 'vitrine')."""
    r = db.produits.delete_many({"vitrine": {"$exists": False}})
    return {"message": "Anciens produits supprimés", "supprimes": r.deleted_count}

# ─── PURGE temporaire par clé (À RETIRER APRÈS USAGE) ───
@app.delete("/api/admin/purge-cle/{cle}")
def purge_par_cle(cle: str):
    if cle != "Sani2026Purge":
        raise HTTPException(403, "Clé invalide")
    r = db.produits.delete_many({"vitrine": {"$exists": False}})
    return {"message": "Anciens produits supprimés", "supprimes": r.deleted_count}

# ─── SEED (admin + catalogue de démo) ───────────────────
@app.post("/api/seed")
def seed_data():
    if db.users.count_documents({"role": "admin"}) == 0:
        hashed = bcrypt.hashpw("admin1234".encode(), bcrypt.gensalt()).decode()
        db.users.insert_one({
            "nom": "Admin", "prenom": "SANI-FÉRÉ", "email": "admin@sanifere.ml",
            "telephone": "70000000", "mot_de_passe": hashed, "role": "admin",
            "ville": "Bamako", "actif": True, "date_inscription": datetime.utcnow(),
        })

    if db.produits.count_documents({}) == 0:
        demo = [
            {"nom": "Body manches longues coton bio (lot de 3)", "prix": 9500, "prix_barre": 12000, "frais_livraison": 2500, "categorie": "bebe", "vitrine": "okaidi", "taille": "6-12 mois"},
            {"nom": "Pyjama dors-bien naissance velours", "prix": 7000, "frais_livraison": 2000, "categorie": "naissance", "vitrine": "obaibi", "taille": "0-3 mois"},
            {"nom": "Robe à fleurs été fille", "prix": 11500, "prix_barre": 15000, "frais_livraison": 3000, "categorie": "fille", "vitrine": "okaidi", "taille": "4 ans"},
            {"nom": "Salopette en jean garçon", "prix": 13000, "frais_livraison": 3500, "categorie": "garcon", "vitrine": "okaidi", "taille": "5 ans"},
            {"nom": "Baskets montantes premiers pas", "prix": 9000, "frais_livraison": 2500, "categorie": "chaussures", "vitrine": "obaibi", "taille": "21"},
            {"nom": "Gigoteuse 0-6 mois étoiles", "prix": 12000, "prix_barre": 16000, "frais_livraison": 3000, "categorie": "naissance", "vitrine": "okaidi", "taille": "0-6 mois"},
        ]
        for p in demo:
            p.update({"description": "", "images": [], "marque": p["vitrine"].upper(),
                      "disponible": True, "nb_vues": 0, "nb_favoris": 0,
                      "date_creation": datetime.utcnow()})
            db.produits.insert_one(p)

    return {"message": "Seed OK", "admin": "admin@sanifere.ml / admin1234"}
