const jwt = require('jsonwebtoken');

const  generateTokenAndSetCookie = (id,res) =>{
    const token = jwt.sign({ id }, process.env.SECRET, { expiresIn: 60 * 15});
  
    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
		sameSite: "strict",
		maxAge: 60 * 15,
    });

    return token;
}

module.exports = { generateTokenAndSetCookie};
