const jwt = require('jsonwebtoken');
const requireAuth = (req, res, next) => {
  const token = req.cookies.token;
  if (token) {
    jwt.verify(token, process.env.SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ status: 'Erro', message: "Invalid token" });
      } else {
        req.user = decoded; 
        next(); 
      }
    });
  } else {
    return res.status(401).json({ status: 'Erro', message: "No token provided" });
  }

};
// check current user
const requireRefreshToken = (req, res, next) => {
  try {
    const refreshTokenCookie = req.cookies.refreshToken;
    if (!refreshTokenCookie) {
      return res.status(401).json({ status: 'error', message: 'No token found' });
    }
    jwt.verify(refreshTokenCookie,process.env.JWT_REFRESH, (err, decoded)=> {
      if(err){
        return res.status(403).json({ status: 'error', message: 'Invalid or expired token' });
      }else{
        req.user= decoded
        next();
      }
    })
  } catch (err) {
    return res.status(500).json({ msg: "A server error occurred, please try again later!" });
  } 
};

module.exports = { requireAuth, requireRefreshToken};