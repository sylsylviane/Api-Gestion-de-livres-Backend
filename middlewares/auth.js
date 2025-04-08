const jwt = require('jsonwebtoken');

/**
 *  Middleware d'authentification pour vérifier la validité du token JWT
 *  et extraire les informations de l'utilisateur.
 * @param {*} req 
 * @param {*} res 
 * @param {*} next  
 * @returns 
 */
async function auth(req, res, next){
  // Récupération du token dans le header de la requête HTTP
  const jeton =
    req.headers["authorization"] && req.headers["authorization"].split(" ")[1]; 

  // Si le token n'est pas fourni, on renvoie une erreur 401 (non autorisé)
  if (!jeton)
    return res.status(401).json({ msg: "Accès refusé. Pas de jeton fourni." });

  // On vérifie le token avec la clé secrète pour le décoder avec la méthode decode de jwt. process.env.SECRET_JETON est la clé secrète stockée dans le fichier .env
  const decode = await jwt.decode(jeton, process.env.JWT_SECRET);
  if (!decode)
    return res.status(401).json({ msg: "Accès refusé. Jeton invalide." }); // Si le token est invalide, on renvoie une erreur 401 (non autorisé)

  // On stocke les informations de l'utilisateur dans la requête HTTP pour les utiliser dans les routes protégées par le middleware auth. Pas obligatoire, mais utile pour récupérer les informations de l'utilisateur connecté.
  req.utilisateur = decode;

  next(); 
}

module.exports = auth;