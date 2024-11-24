const User = require("../models/User");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto')

const { generateTokenAndSetCookie } = require("../utils/auth");
const { send } = require("../mailtrap/mailtrap")
const { sendVerificationEmail, sendPasswordResetEmail } = require("../mailtrap/emails")

/**
 * @swagger
 * /auth/signup:
 *   post:
 *     summary: Cadastra um novo usuário.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: user
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: senha123
 *             required:
 *               - name
 *               - email
 *               - password
 *     responses:
 *       200:
 *         description: Usuário cadastrado com sucesso.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Usuário cadastrado com sucesso."
 *       400:
 *         description: O usuário já existe ou dados inválidos.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "O usuário já existe."
 *       500:
 *         description: Falha no registro devido a erro interno do servidor.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Falha no registro."
 */
module.exports.register = async (req, res) => {
  const {name, email, password} = req.body;
  
  try {
    // check if user exits
    const userExists = await User.findOne({ email: email });
    if(userExists){
      return res.status(400).json({success:false, message: 'User already exists'})
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

    generateTokenAndSetCookie(user._id,res)
      
    await sendVerificationEmail(user.email, verificationToken);

    res.status(200).json({ success: true, message:'User registered sucessfully',
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
			return res.status(400).json({ success: false, message: "Invalid or expired verification code" });
		}

		user.isVerified = true;
		user.verificationToken = undefined;
		user.verificationTokenExpiresAt = undefined;
		await user.save();

		res.status(200).json({
			success: true,
			message: "Email verified successfully",
			user: {
				...user._doc,
				password: undefined,
			},
		});
	} catch (error) {
		console.log("error in verifyEmail ", error);
		res.status(500).json({ success: false, message: "Server error" });
	}
}
/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Realiza o login de um usuário.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: senha123
 *             required:
 *               - email
 *               - password
 *     responses:
 *       200:
 *         description: Login bem-sucedido. Retorna um token de autenticação.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       400:
 *         description: O usuário não existe.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "O usuário não existe."
 *       401:
 *         description: E-mail ou senha incorretos.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "E-mail ou senha incorretos."
 *       500:
 *         description: Erro durante o processo de login.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Erro interno do servidor."
 */
module.exports.login = async(req, res) => {
    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email: email })
      if(!user){
        return res.status(400).json({success: false, message: 'User does not exist'})
      }
      // check if password match
      const checkPassword = await bcrypt.compare(password, user.password);
  
      if (!checkPassword) {
        return res.status(401).json({ success: false, message: "Incorrect email or password" });
      }
      const token = generateTokenAndSetCookie(user._id, res)
      user.lastLogin = new Date();
		  await user.save();
      return res.status(200).json({success: true, message: "logged in successfully", token});
    } catch (err) {
      console.log(err)
      res.status(500).json({success: false,message: 'Error during login process'})
    }
}
/**
 * @openapi
 * /auth/profile:
 *   get:
 *     summary: Retorna as informações do perfil do usuário.
 *     description: Este endpoint recupera as informações do perfil do usuário autenticado. O usuário deve fornecer um token de autenticação válido no cabeçalho da solicitação.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sucesso ao recuperar as informações do perfil.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "12345"
 *                     name:
 *                       type: string
 *                       example: "João da Silva"
 *                     email:
 *                       type: string
 *                       example: "joao.silva@example.com"
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                       example: "2024-01-01T12:00:00Z"
 *       401:
 *         description: Token de autenticação inválido ou não fornecido.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Token de autenticação inválido ou não fornecido."
 *       500:
 *         description: Erro ao recuperar informações do usuário.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Erro ao recuperar informações do usuário."
 */

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

/**
 * @openapi
 * /auth/forgot-password:
 *   post:
 *     summary: Recupera a senha do usuário.
 *     description: Este endpoint permite que um usuário recupere sua senha enviando um e-mail para o endereço fornecido. Se o e-mail estiver registrado, um e-mail de recuperação será enviado ao usuário.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *             required:
 *               - email
 *     responses:
 *       200:
 *         description: E-mail enviado para recuperação de senha com sucesso.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 mess age:
 *                   type: string
 *                   example: "E-mail de recuperação de senha enviado com sucesso."
 *       401:
 *         description: Erro ao enviar e-mail de recuperação.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Erro ao enviar e-mail de recuperação. Tente novamente."
 *       422:
 *         description: O e-mail fornecido não está associado a nenhum usuário registrado.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "O e-mail fornecido não está associado a nenhum usuário registrado."
 *       500:
 *         description: Erro interno ao tentar recuperar a senha.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Erro interno ao tentar recuperar a senha. Tente novamente mais tarde."
 */
module.exports.forgotPassword = async(req, res) =>{
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(422).json({ success: false, message: "User not found"});
    }
    
    // Generate reset token
		const resetToken = crypto.randomBytes(20).toString("hex");
		const resetTokenExpiresAt = Date.now() + 1 * 60 * 60 * 1000; // 1 hour

		user.resetPasswordToken = resetToken;
		user.resetPasswordExpiresAt = resetTokenExpiresAt;

		await user.save();
    // send email
		await sendPasswordResetEmail(user.email, `http://localhost:5173/reset-password/${resetToken}`);

    res.status(200).json({ success: true, message: "Password reset link sent to your email" });
  } catch (err) {
    console.log("Error in forgotPassword ", err);
    return res.status(500).json({ success: false, message: err.message});
  }    
}
/**
 * @openapi
 * /auth/reset-password:
 *   post:
 *     summary: Redefine a senha do usuário.
 *     description: Este endpoint permite que um usuário redefina sua senha usando um token de recuperação válido enviado anteriormente para o e-mail do usuário. O novo token de senha deve ser incluído no cabeçalho ou no corpo da solicitação, conforme a implementação.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 description: Token de recuperação enviado para o e-mail do usuário.
 *                 example: "a1b2c3d4e5f6g7h8i9j0"
 *               newPassword:
 *                 type: string
 *                 description: Nova senha que será definida para o usuário.
 *                 example: novaSenha123
 *             required:
 *               - token
 *               - newPassword
 *     responses:
 *       200:
 *         description: Senha redefinida com sucesso.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Senha redefinida com sucesso."
 *       400:
 *         description: Solicitação inválida, verifique os dados fornecidos.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Dados inválidos fornecidos."
 *       401:
 *         description: Token de recuperação inválido ou expirado.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Token de recuperação inválido ou expirado."
 *       500:
 *         description: Erro interno ao tentar redefinir a senha.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Erro interno ao tentar redefinir a senha. Tente novamente mais tarde."
 */

module.exports.resetPassword = async(req, res) => {
  const {token} = req.params;
  const {password} = req.body;
  try {
    const verify = jwt.verify(token, process.env.SECRET)
    const id = verify.id;
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);
    const user = await User.findByIdAndUpdate({_id:id}, { password: passwordHash})
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    return res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError) {
      return res.status(400).json({ message: "Invalid token" });
    }
    return res.status(500).json({ message: "Cannot reset password, try again." });
  }
};
/**
 * @openapi
 * /auth/logout:
 *   get:
 *     summary: Faz logout do usuário.
 *     description: Este endpoint permite que um usuário faça logout, invalidando o token de autenticação atual. O usuário deve fornecer um token válido no cabeçalho da solicitação para que o logout seja bem-sucedido.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout bem-sucedido. O token de autenticação foi invalidado.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Logout realizado com sucesso."
 *       401:
 *         description: Token de autenticação inválido ou não fornecido.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Token de autenticação inválido ou não fornecido."
 *       500:
 *         description: Erro interno ao tentar realizar o logout.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Erro interno ao tentar realizar o logout. Tente novamente mais tarde."
 */

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

