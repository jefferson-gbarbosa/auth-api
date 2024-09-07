const jwt = require('jsonwebtoken');
const logger = require("../utils/logger")

const requireAuth = (req, res, next) => {
  const token = req.cookies.token;
  if(token){
    jwt.verify(token, process.env.SECRET, (err, decoded)=> {
      if(err){
        logger.error("No token found")
        res.json({ status: 'Erro', message: "No token found"});
      }else{
        req.user= decoded
        next();
      }
    })
  }else{
    logger.error("A server error occurred, please try again later!")
    res.json({ status: 'Erro', message: "A server error occurred, please try again later!"});
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