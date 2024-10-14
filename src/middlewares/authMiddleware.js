const jwt = require('jsonwebtoken');
const logger = require("../utils/logger")

const requireAuth = (req, res, next) => {

  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.split(' ')[1]
    : req.body.token || req.query.token || req.headers['x-access-token'];

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
  const refreshTokenCookie = req.cookies.refreshToken;
  console.log(refreshTokenCookie)
  if (!refreshTokenCookie) {
    logger.error("No refresh token found");
    return res.status(401).json({ status: 'Erro', message: "No refresh token provided" });
  }

  jwt.verify(refreshTokenCookie, process.env.JWT_REFRESH, (err, decoded) => {
    if (err) {
      logger.error("Invalid refresh token: " + err.message);
      return res.status(401).json({ status: 'Erro', message: "Invalid refresh token" });
    } else {
      req.user = decoded; // Armazena as informações decodificadas no objeto de requisição
      next(); // Chama o próximo middleware ou rota
    }
  });
};

module.exports = { requireAuth, requireRefreshToken };