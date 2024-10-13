const jwt = require('jsonwebtoken');
const logger = require("../utils/logger")

const requireAuth = (req, res, next) => {
  console.log('Cookies: ', req.cookies);
  const token = req.cookies.token;
  if (token) {
    jwt.verify(token, process.env.SECRET, (err, decoded) => {
      if (err) {
        logger.error("Token verification failed: " + err.message);
        return res.status(401).json({ status: 'Erro', message: "Invalid token" });
      } else {
        req.user = decoded; // Armazena as informações decodificadas no objeto de requisição
        next(); // Chama o próximo middleware ou rota
      }
    });
  } else {
    logger.error("No token provided");
    return res.status(401).json({ status: 'Erro', message: "No token provided" });
  }

};

// check current user
const requireRefreshToken = (req, res, next) => {
  try {
    const refreshTokenCookie = req.cookies.refreshToken;
    jwt.verify(refreshTokenCookie,process.env.JWT_REFRESH, (err, decoded)=> {
      if(err){
        logger.error("No token found")
        res.json({ status: 'Erro', message: "No token found"});
      }else{
        req.user= decoded
        next();
      }
    })
  } catch (err) {
    logger.error("A server error occurred, please try again later!")
    return res.status(500).json({ msg: "A server error occurred, please try again later!" });
  } 
};


module.exports = { requireAuth, requireRefreshToken };