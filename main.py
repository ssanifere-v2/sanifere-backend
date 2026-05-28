from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
from bson import ObjectId
from bson.errors import InvalidId
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="SANI-FÉRÉ API", version="1.0.0")

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
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload
    except:
        return None

def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = get_current_user(credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Non authentifié")
    return user

# ─── Modèles ───────────────────────────────────────────
class InscriptionUser(BaseModel):
    nom: str
    prenom: str
    email: str
    telephone: str
    mot_de_passe: str
    role: str = "acheteur"  # acheteur ou vendeur
    ville: Optional[str] = "Bamako"

class ConnexionUser(BaseModel):
    email: str
    mot_de_passe: str

class ProduitCreate(BaseModel):
    nom: str
    description: str
    prix: float
    categorie: str
    etat: str = "neuf"  # neuf, bon_etat, usage
    images: List[str] = []
    taille: Optional[str] = None
    marque: Optional[str] = None
    quantite: int = 1
    ville: Optional[str] = "Bamako"

class ProduitUpdate(BaseModel):
    nom: Optional[str] = None
    description: Optional[str] = None
    prix: Optional[float] = None
    categorie: Optional[str] = None
    etat: Optional[str] = None
    images: Optional[List[str]] = None
    taille: Optional[str] = None
    marque: Optional[str] = None
    quantite: Optional[int] = None
    disponible: Optional[bool] = None

class CommandeCreate(BaseModel):
    produit_id: str
    quantite: int = 1
    adresse_livraison: str
    telephone_acheteur: str
    mode_paiement: str = "orange_money"

# ─── Root ───────────────────────────────────────────────
@app.get("/")
def root():
    return {"message": "SANI-FÉRÉ API v1.0", "status": "ok"}

# ─── AUTH ───────────────────────────────────────────────
@app.post("/api/auth/inscription")
def inscription(data: InscriptionUser):
    if db.users.find_one({"email": data.email}):
        raise HTTPException(400, "Email déjà utilisé")
    if db.users.find_one({"telephone": data.telephone}):
        raise HTTPException(400, "Téléphone déjà utilisé")

    hashed = bcrypt.hashpw(data.mot_de_passe.encode(), bcrypt.gensalt()).decode()
    user = {
        "nom": data.nom,
        "prenom": data.prenom,
        "email": data.email,
        "telephone": data.telephone,
        "mot_de_passe": hashed,
        "role": data.role,
        "ville": data.ville,
        "avatar": None,
        "note_moyenne": 0,
        "nb_ventes": 0,
        "date_inscription": datetime.utcnow(),
        "actif": True
    }
    result = db.users.insert_one(user)
    token = create_token(str(result.inserted_id), data.role)
    return {"token": token, "role": data.role, "message": "Inscription réussie"}

@app.post("/api/auth/connexion")
def connexion(data: ConnexionUser):
    user = db.users.find_one({"email": data.email})
    if not user:
        raise HTTPException(401, "Email ou mot de passe incorrect")
    if not bcrypt.checkpw(data.mot_de_passe.encode(), user["mot_de_passe"].encode()):
        raise HTTPException(401, "Email ou mot de passe incorrect")
    token = create_token(str(user["_id"]), user.get("role", "acheteur"))
    return {
        "token": token,
        "role": user.get("role"),
        "user": serialize({k: v for k, v in user.items() if k != "mot_de_passe"})
    }

@app.get("/api/auth/profil")
def mon_profil(user=Depends(require_auth)):
    u = db.users.find_one({"_id": ObjectId(user["sub"])})
    if not u:
        raise HTTPException(404, "Utilisateur non trouvé")
    u.pop("mot_de_passe", None)
    return serialize(u)

# ─── PRODUITS ───────────────────────────────────────────
@app.get("/api/produits")
def lister_produits(
    page: int = 1,
    limit: int = 20,
    categorie: Optional[str] = None,
    etat: Optional[str] = None,
    ville: Optional[str] = None,
    q: Optional[str] = None,
    vendeur_id: Optional[str] = None,
    min_prix: Optional[float] = None,
    max_prix: Optional[float] = None,
):
    query = {"disponible": True}
    if categorie:
        query["categorie"] = {"$regex": categorie, "$options": "i"}
    if etat:
        query["etat"] = etat
    if ville:
        query["ville"] = {"$regex": ville, "$options": "i"}
    if q:
        query["$or"] = [
            {"nom": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"marque": {"$regex": q, "$options": "i"}},
        ]
    if vendeur_id:
        try:
            query["vendeur_id"] = ObjectId(vendeur_id)
        except:
            pass
    if min_prix or max_prix:
        query["prix"] = {}
        if min_prix:
            query["prix"]["$gte"] = min_prix
        if max_prix:
            query["prix"]["$lte"] = max_prix

    skip = (page - 1) * limit
    total = db.produits.count_documents(query)
    produits = list(db.produits.find(query).sort("date_creation", -1).skip(skip).limit(limit))

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "produits": serialize(produits)
    }

@app.get("/api/produits/{produit_id}")
def get_produit(produit_id: str):
    try:
        p = db.produits.find_one({"_id": ObjectId(produit_id)})
    except:
        raise HTTPException(400, "ID invalide")
    if not p:
        raise HTTPException(404, "Produit non trouvé")
    # Info vendeur
    vendeur = db.users.find_one({"_id": p.get("vendeur_id")})
    result = serialize(p)
    if vendeur:
        result["vendeur"] = serialize({
            "id": str(vendeur["_id"]),
            "nom": vendeur.get("nom"),
            "prenom": vendeur.get("prenom"),
            "ville": vendeur.get("ville"),
            "note_moyenne": vendeur.get("note_moyenne", 0),
            "nb_ventes": vendeur.get("nb_ventes", 0),
        })
    return result

@app.post("/api/produits")
def creer_produit(data: ProduitCreate, user=Depends(require_auth)):
    produit = {
        **data.dict(),
        "vendeur_id": ObjectId(user["sub"]),
        "disponible": True,
        "nb_vues": 0,
        "nb_favoris": 0,
        "date_creation": datetime.utcnow(),
    }
    result = db.produits.insert_one(produit)
    return {"id": str(result.inserted_id), "message": "Produit créé"}

@app.put("/api/produits/{produit_id}")
def modifier_produit(produit_id: str, data: ProduitUpdate, user=Depends(require_auth)):
    try:
        p = db.produits.find_one({"_id": ObjectId(produit_id)})
    except:
        raise HTTPException(400, "ID invalide")
    if not p:
        raise HTTPException(404, "Produit non trouvé")
    if str(p["vendeur_id"]) != user["sub"]:
        raise HTTPException(403, "Non autorisé")
    update = {k: v for k, v in data.dict().items() if v is not None}
    db.produits.update_one({"_id": ObjectId(produit_id)}, {"$set": update})
    return {"message": "Produit mis à jour"}

@app.delete("/api/produits/{produit_id}")
def supprimer_produit(produit_id: str, user=Depends(require_auth)):
    try:
        p = db.produits.find_one({"_id": ObjectId(produit_id)})
    except:
        raise HTTPException(400, "ID invalide")
    if not p:
        raise HTTPException(404, "Produit non trouvé")
    if str(p["vendeur_id"]) != user["sub"] and user.get("role") != "admin":
        raise HTTPException(403, "Non autorisé")
    db.produits.delete_one({"_id": ObjectId(produit_id)})
    return {"message": "Produit supprimé"}

# ─── CATÉGORIES ─────────────────────────────────────────
@app.get("/api/categories")
def lister_categories():
    cats = [
        {"nom": "Mode Femme", "emoji": "👗", "slug": "mode-femme"},
        {"nom": "Mode Homme", "emoji": "👔", "slug": "mode-homme"},
        {"nom": "Enfants", "emoji": "👶", "slug": "enfants"},
        {"nom": "Électronique", "emoji": "📱", "slug": "electronique"},
        {"nom": "Maison & Déco", "emoji": "🏠", "slug": "maison"},
        {"nom": "Sport & Loisirs", "emoji": "⚽", "slug": "sport"},
        {"nom": "Beauté & Soins", "emoji": "💄", "slug": "beaute"},
        {"nom": "Agriculture", "emoji": "🌾", "slug": "agriculture"},
        {"nom": "Livres & Fournitures", "emoji": "📚", "slug": "livres"},
        {"nom": "Alimentation", "emoji": "🍎", "slug": "alimentation"},
        {"nom": "Auto-Moto", "emoji": "🚗", "slug": "auto-moto"},
        {"nom": "Services", "emoji": "🔧", "slug": "services"},
    ]
    return cats

# ─── COMMANDES ──────────────────────────────────────────
@app.post("/api/commandes")
def creer_commande(data: CommandeCreate, user=Depends(require_auth)):
    try:
        p = db.produits.find_one({"_id": ObjectId(data.produit_id)})
    except:
        raise HTTPException(400, "ID produit invalide")
    if not p:
        raise HTTPException(404, "Produit non trouvé")
    if not p.get("disponible"):
        raise HTTPException(400, "Produit non disponible")

    commande = {
        "produit_id": ObjectId(data.produit_id),
        "acheteur_id": ObjectId(user["sub"]),
        "vendeur_id": p["vendeur_id"],
        "quantite": data.quantite,
        "prix_total": p["prix"] * data.quantite,
        "adresse_livraison": data.adresse_livraison,
        "telephone_acheteur": data.telephone_acheteur,
        "mode_paiement": data.mode_paiement,
        "statut": "en_attente",
        "date_commande": datetime.utcnow(),
    }
    result = db.commandes.insert_one(commande)
    return {"id": str(result.inserted_id), "message": "Commande créée", "prix_total": commande["prix_total"]}

@app.get("/api/mes-commandes")
def mes_commandes(user=Depends(require_auth)):
    commandes = list(db.commandes.find({"acheteur_id": ObjectId(user["sub"])}).sort("date_commande", -1))
    return serialize(commandes)

@app.get("/api/mes-ventes")
def mes_ventes(user=Depends(require_auth)):
    ventes = list(db.commandes.find({"vendeur_id": ObjectId(user["sub"])}).sort("date_commande", -1))
    return serialize(ventes)

# ─── FAVORIS ────────────────────────────────────────────
@app.post("/api/favoris/{produit_id}")
def toggle_favori(produit_id: str, user=Depends(require_auth)):
    uid = ObjectId(user["sub"])
    try:
        pid = ObjectId(produit_id)
    except:
        raise HTTPException(400, "ID invalide")
    existing = db.favoris.find_one({"user_id": uid, "produit_id": pid})
    if existing:
        db.favoris.delete_one({"_id": existing["_id"]})
        db.produits.update_one({"_id": pid}, {"$inc": {"nb_favoris": -1}})
        return {"favori": False}
    else:
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

# ─── VENDEUR ────────────────────────────────────────────
@app.get("/api/vendeurs/{vendeur_id}")
def profil_vendeur(vendeur_id: str):
    try:
        u = db.users.find_one({"_id": ObjectId(vendeur_id)})
    except:
        raise HTTPException(400, "ID invalide")
    if not u:
        raise HTTPException(404, "Vendeur non trouvé")
    u.pop("mot_de_passe", None)
    u.pop("email", None)
    return serialize(u)

@app.get("/api/vendeurs/{vendeur_id}/produits")
def produits_vendeur(vendeur_id: str, page: int = 1, limit: int = 20):
    try:
        vid = ObjectId(vendeur_id)
    except:
        raise HTTPException(400, "ID invalide")
    query = {"vendeur_id": vid, "disponible": True}
    total = db.produits.count_documents(query)
    produits = list(db.produits.find(query).sort("date_creation", -1).skip((page-1)*limit).limit(limit))
    return {"total": total, "produits": serialize(produits)}

# ─── ADMIN ──────────────────────────────────────────────
@app.get("/api/admin/stats")
def admin_stats(user=Depends(require_auth)):
    if user.get("role") != "admin":
        raise HTTPException(403, "Accès refusé")
    return {
        "users": db.users.count_documents({}),
        "produits": db.produits.count_documents({}),
        "commandes": db.commandes.count_documents({}),
        "vendeurs": db.users.count_documents({"role": "vendeur"}),
    }

# ─── SEED ───────────────────────────────────────────────
@app.post("/api/seed")
def seed_data():
    if db.produits.count_documents({}) > 0:
        return {"message": "Base déjà peuplée"}

    # Créer vendeur demo
    hashed = bcrypt.hashpw("demo1234".encode(), bcrypt.gensalt()).decode()
    vendeur = {
        "nom": "Koné", "prenom": "Aissata",
        "email": "demo@sanifere.ml", "telephone": "70000000",
        "mot_de_passe": hashed, "role": "vendeur",
        "ville": "Bamako", "actif": True,
        "note_moyenne": 4.8, "nb_ventes": 12,
        "date_inscription": datetime.utcnow()
    }
    v_id = db.users.insert_one(vendeur).inserted_id

    produits_demo = [
        {"nom": "Boubou Wax femme taille M", "description": "Magnifique boubou en tissu wax 100% coton", "prix": 12500, "categorie": "mode-femme", "etat": "neuf", "taille": "M", "marque": "Artisanal", "images": [], "ville": "Bamako"},
        {"nom": "Samsung Galaxy A54 128Go", "description": "Téléphone Samsung Galaxy A54 en très bon état", "prix": 195000, "categorie": "electronique", "etat": "bon_etat", "marque": "Samsung", "images": [], "ville": "Bamako"},
        {"nom": "Nike Air Force 1 taille 42", "description": "Basket Nike Air Force 1 neuves jamais portées", "prix": 35000, "categorie": "mode-homme", "etat": "neuf", "taille": "42", "marque": "Nike", "images": [], "ville": "Ségou"},
        {"nom": "Set jouets bébé 0-3 ans", "description": "Ensemble de jouets éducatifs pour bébé", "prix": 9500, "categorie": "enfants", "etat": "neuf", "images": [], "ville": "Bamako"},
        {"nom": "Robe pour fillette 5 ans", "description": "Jolie robe d'occasion en très bon état", "prix": 4500, "categorie": "enfants", "etat": "bon_etat", "taille": "5 ans", "images": [], "ville": "Bamako"},
        {"nom": "Laptop Dell Core i5 8Go RAM", "description": "Ordinateur portable Dell performant", "prix": 280000, "categorie": "electronique", "etat": "bon_etat", "marque": "Dell", "images": [], "ville": "Bamako"},
    ]

    for p in produits_demo:
        p["vendeur_id"] = v_id
        p["disponible"] = True
        p["nb_vues"] = 0
        p["nb_favoris"] = 0
        p["date_creation"] = datetime.utcnow()
        db.produits.insert_one(p)

    return {"message": "Données de démo créées", "vendeur_demo": "demo@sanifere.ml / demo1234"}
