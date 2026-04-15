require("dotenv").config()
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors')
const router = require('./self_modules/routes/routes');
const routerSecure = require('./self_modules/routes/routesSecure');
const authorize = require('./self_modules/middlewares/authorize');
const corsOptions = require('./self_modules/middlewares/cors');
const cookieParser = require('cookie-parser');
const logger = require('./self_modules/middlewares/logger');
const dataController = require('./controllers/dataController');
const checkIfAdmin = require('./self_modules/middlewares/checkIfAdmin');

const app = express();

app.use(express.urlencoded({extended:true}));
app.use(bodyParser.json({limit:"1.1MB"}));
app.use(express.static('public'));
app.use(cookieParser());
app.use(cors(corsOptions))
// 📋 Forensic logging – logs every request to logs/access.log
app.use(logger);

// Middleware : si la requête a un header 'token', c'est une requête API
const isApiRequest = (req, res, next) => {
    if (req.headers.token) {
        next(); // C'est une requête API, continuer
    } else {
        next('route'); // Pas de token = navigation navigateur, passer au catch-all
    }
};

// Route publique (pas besoin de token)
app.post('/connection', dataController.connectUser);

// Routes protégées : seulement si header 'token' est présent
app.get('/user', isApiRequest, authorize, dataController.fetchDataUser);
app.get('/admin', isApiRequest, authorize, checkIfAdmin, dataController.getVictory);
app.get('/blog', isApiRequest, authorize, dataController.fetchBlogMessages);
app.post('/blog', authorize, dataController.createBlogmessage);

// SPA catch-all : toutes les autres routes servent index.html (React)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const port = process.env.PORT || 3001

app.listen(port, () => {
    console.info(`[SERVER] Listening on http://localhost:${port}`); 
})