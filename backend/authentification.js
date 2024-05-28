const express = require("express") //importer le module express
const mysql = require("mysql") //importer lemodule mysql
const bodyparser = require("body-parser") //module permettant d'extraire et traiter les données du corp des requêtes http (POST, PUT, DELETE)
const jwt = require("jsonwebtoken") //est un formt compact pour stocker les informations
const bcrypt = require("bcryptjs") //module permettant de hacher les mots de passes et informations sensibles et permet de comparer aussi un mot de passe entré avec une autre contenu dans la base de donnée 

//créer une application express
const app = express() 
const port = 3000
const tokenKey = 'Ken20033@'

//analyser toutes les requêtes entrantes avec un type de contenu application/json pour le rendre disponible dans le req.body sous forme d'objet javascript
app.use(bodyparser.json()) 

//connexion a mysql
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'comparateur'
})

db.connect((err) => {
    if(err){
        console.log("erreur de connexion a la base de donnée")
        throw err
    }
    console.log("connexion a la base de donnée mysql réussi")
})

//route post pour l'authentiication de l'utilisateur avec l'url /login
app.post('/login', (req, res) => {
    const {username, password} = req.body //on extrait les deux variables username et password du req.body (req qui est la requête lancé et req.body qui est le corp de requête)
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) =>{ //le ? evite les attaques par requête sql, le ? est remplacé après par la valeur réelle contenu dans le username
        if(err){
            console.log("operation de selection non effectué")
            console.log(err)
        }

        if(results.lenght === 0){
            console.log("nom d'utilisateur ou mot passe incorret 1")
            return res.status(400).json({message: 'nom d\'utilisateur ou mot de passe invalide'}) //si ce nom d'utiisateur n'existe pas retourner l'erreur 400
        }

        const user = results[0]; //si le user existe enregistrer le premier trouvé
        console.log("utilisateurs trouvé")

        bcrypt.compare(password, user.password, (err, isMatch) =>{ //compare le password extrait dans la requête avec le password extrait dans la base de donnée et stcké dans le user
            if(err){
                console.log("erreur lors de la comparaison")
                console.log(err)
            }

            if(isMatch){
                const token = jwt.sign({username: user.username}, tokenKey) //a partir du username et du tokenKey on génére un token (Un token est une chaîne de caractères générée de manière unique et utilisée comme preuve didentité. Dans ce cas, il s'agit spécifiquement d'un JSON Web Token (JWT))
                console.log("nom d'utilisateur et mot de passe correct après comparaison")
                return res.status(200).json({token}) //on renvoie le token au client dans le corps de la reponse
            }else{
                console.log("nom d'utilisateur ou mot passe incorret 2")
                return res.status(400).json({message: 'nom d\'utilisateur ou mot de passe incorrect'})
            }
        })
    }) 
})


//
const veriyToken = (req, res, next) =>{
    const token = req.headers.authorization; //on extrait le token dans le corps de la requête

    if(!token){
        return res.status(403).json({message: 'no token provided'})
    }

    //s'il y'a un token
    jwt.verify(token, tokenKey, (err, decoded) => { //vérifie que le token est correct grace a la clé tokenKey utilisé lors de l'encodage
        if(err){
            return res.status(401).json({message: 'pas autorisé'})
        }

        req.user = decoded //modifie la requete en ajoutant le nom du user obtenue après avoir decodé le token
        next()
    })
}

//
app.get('\protected',veriyToken, (req, res) =>{
    res.statut(200).json({message : 'route protégée', user: req.user})
})

//start server
app.listen(port, () =>{
    console.log(`le server est démarré sur le port ${port}`)
})