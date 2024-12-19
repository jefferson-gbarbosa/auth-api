const jwt = require('jsonwebtoken');

const  generateTokenAndSetCookie = (id,res) =>{
    const token = jwt.sign({ id }, process.env.SECRET, { expiresIn: 60 * 15});
  
    res.cookie('token', token, {
        httpOnly: true,
        // sameSite: "strict",
        // expires: new Date(Date.now() + 60 * 15 * 1000),
    });

    return token;
}

module.exports = { generateTokenAndSetCookie};
