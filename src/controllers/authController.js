const User = require("../models/User");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto')
const { sendVerificationEmail, sendPasswordResetEmail, sendResetSuccessEmail } = require("../mailtrap/emails")
module.exports.register = async (req, res) => {
  try {
    const {name, email, password} = req.body;

    // Validação de entrada
    if(!name || !email || !password){
      return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }
    // check if user exits
    const userExists = await User.findOne({ email: email });
    if(userExists){
      return res.status(409).json({message: 'User already exists'})
    }
    
    // Creat password
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);
    const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();

    // Creat User
    const user = new User({
      name,
      email,
      password: passwordHash,
      verificationToken,
      verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    })
    await user.save();
    
    await sendVerificationEmail(user.email, verificationToken);

    res.status(200).json({ message:'User registered sucessfully',
      user: {
				...user._doc,
				password: undefined,
			}
    })
  } catch (err) {
    console.log(err)
    res.status(500).json({message: 'Registration failed.'})
  }
}

module.exports.verifyEmail = async(req, res) =>{
  const { code } = req.body;
	try {
		const user = await User.findOne({
			verificationToken: code,
			verificationTokenExpiresAt: { $gt: Date.now() },
		});

		if (!user) {
			return res.status(400).json({ message: "Invalid or expired verification code" });
		}

		user.isVerified = true;
		user.verificationToken = undefined;
		user.verificationTokenExpiresAt = undefined;
		await user.save();

		res.status(200).json({
			message: "Email verified successfully",
			user: {
				...user._doc,
				password: undefined,
			},
		});
	} catch (error) {
		console.log("error in verifyEmail ", error);
		res.status(500).json({ message: "Server error" });
	}
}

module.exports.login = async(req, res) => {
    const { email, password } = req.body;
     try {
      if (!email || !password) {
        return res.status(400).json({success: false, message: 'Email and password are required' });
      }

      const user = await User.findOne({ email: email })
      if(!user){
        return res.status(400).json({success: false,message: 'User does not exist'})
      }
      // check if password match
      const checkPassword = await bcrypt.compare(password, user.password);
  
      if (!checkPassword) {
        return res.status(401).json({ success: false, message: "Incorrect email or password" });
      }
      const token = jwt.sign({ id: user.id }, process.env.SECRET, { expiresIn: '15m'});
      const expireDate = new Date(Date.now() + 60000); 

      res.cookie('token', token, {
        httpOnly: true,
        expires: expireDate
      });

      const refreshToken = jwt.sign({ id: user.id }, process.env.JWT_REFRESH, { expiresIn: '1d'});
      res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 })

      user.lastLogin = new Date();
		  await user.save();
      
      return res.status(200).json({message: "logged in successfully", token});
    } catch (err) {
      console.error('Error during login process:', err.message || err);
      res.status(500).json({message: 'Error during login process'})
    }
}
module.exports.infoUser = async (req, res) => {
  const id = req.user.id;
  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({ name: user.name, email: user.email });
  } catch (err) {
    return res.status(500).json({ message: "Error retrieving user info" });
  }
};

module.exports.refreshToken = async(req, res) => {
  const id = req.user.id
  try {
    const user = await User.findById(id);
    const token = jwt.sign({ id: user.id }, process.env.SECRET, { expiresIn: '15m'});
    const expireDate = new Date(Date.now() + 60000); 
    res.cookie('token', token, {
      httpOnly: true,
      expires: expireDate
    });
    return res.json({ token });
  } catch (err) {
    return res.status(500).json({ message: "Error generating token for user id!" });
  }
};

module.exports.forgotPassword = async(req, res) =>{
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(422).json({ message: "User not found"});
    }
    
    // Generate reset token
		const resetToken = crypto.randomBytes(20).toString("hex");
		const resetTokenExpiresAt = Date.now() + 1 * 60 * 60 * 1000; // 1 hour
   
		user.resetPasswordToken = resetToken;
		user.resetPasswordExpiresAt = resetTokenExpiresAt;

		await user.save();
    // send email
		await sendPasswordResetEmail(user.email, `http://localhost:5173/reset-password/${resetToken}`);

    res.status(200).json({ message: "Password reset link sent to your email" });
  } catch (err) {
    console.log("Error in forgotPassword ", err);
    return res.status(500).json({ message: err.message});
  }    
}

module.exports.resetPassword = async(req, res) => {
  try {
    const {token} = req.params;
    const {password} = req.body;
  
    const user = await User.findOne({
			resetPasswordToken: token,
			resetPasswordExpiresAt: { $gt: Date.now() },
		});
   
    if (!user) {
      return res.status(400).json({ message: 'Token is invalid or expired' });
    }
  
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);
    
		user.password = passwordHash;
		user.resetPasswordToken = undefined;
		user.resetPasswordExpiresAt = undefined;
		await user.save();

    await sendResetSuccessEmail(user.email);
   
    return res.status(200).json({ message: "Password reset successful"  });
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError) {
      return res.status(400).json({ message: "Invalid token" });
    }
    return res.status(500).json({ message: "Cannot reset password, try again." });
  }
};

module.exports.logout = (req, res) => {
  try {
    // Limpa o cookie de refresh token
    res.clearCookie("token");
    // Retorna uma resposta de sucesso
    res.status(200).json({success: true, message: "Logout successful." });
  } catch (error) {
      res.status(500).json({ message: "An error occurred during logout." });
  }
};

