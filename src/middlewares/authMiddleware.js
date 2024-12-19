const jwt = require('jsonwebtoken');
const requireAuth = (req, res, next) => {
  const token = req.cookies.token;
  if (token) {
    jwt.verify(token, process.env.SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ status: 'Erro', message: "Invalid token" });
      } else {
        req.user = decoded; // Armazena as informações decodificadas no objeto de requisição
        next(); // Chama o próximo middleware ou rota
      }
    });
  } else {
    return res.status(401).json({ status: 'Erro', message: "No token provided" });
  }

};

module.exports = { requireAuth};