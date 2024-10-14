const User = require("../models/User");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const logger = require("../utils/logger")

const generateRefreshToken = (id,res) =>{
  const expiresIn = 60 * 60 * 24 * 30;
  try {
      const refreshToken = jwt.sign({ id }, process.env.JWT_REFRESH, {
          expiresIn,
      });
      return res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          expires: new Date(Date.now() + expiresIn * 1000),
      });
  } catch (err) {
    logger.error(err);
  }
}
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
  // check if user exits
  const userExists = await User.findOne({ email: email });
  if(userExists){
    logger.info('User already exists');
     return res.status(400).json({message: 'User already exists'})
  }
  // Creat password
  const salt = await bcrypt.genSalt();
  const passwordHash = await bcrypt.hash(password, salt);

  // Creat User
  const user = new User({
    name,
    email,
    password: passwordHash,
  })

  try {
    await user.save();
    logger.info("User registered sucessfully")
    res.status(200).json({ user, message:'User registered sucessfully' })
  } catch (err) {
    logger.error("Registration failed.")
    res.status(500).json({message: 'Registration failed.'})
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
    // check if user exits
    const user = await User.findOne({ email: email })

    if(!user){
      logger.warn(`Login attempt with non-existing email: ${email}`);
      return res.status(400).json({message: 'User does not exist'})
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
      logger.warn(`Incorrect password attempt for email: ${email}`);
      return res.status(401).json({ message: "Incorrect email or password" });
    }

    try {
      const token = jwt.sign({ id: user.id }, process.env.SECRET, { expiresIn: 60 * 15});
      res.cookie('token', token, {
        httpOnly: true,
        maxAge: 15 * 60 * 1000 // Duração do cookie (15 minutos)
      });
      generateRefreshToken(user.id,res);
      logger.info(`User ${user.id} logged in successfully.`);
      return res.status(200).json({token});
    } catch (err) {
      logger.error(`Error during login process: ${err.message}`);
      res.status(500).json({message: 'Error during login process'})
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
       // Verifique se o usuário foi encontrado
    if (!user) {
      logger.warn(`User with ID ${id} not found`);
      return res.status(404).json({ message: "User not found" });
    }

    logger.info(`Successfully retrieved user info for ID ${id}`);
    return res.status(200).json({ name: user.name, email: user.email });
  } catch (err) {
    logger.error(`Error retrieving user info for ID ${id}: ${err.message}`);
    return res.status(500).json({ message: "Error retrieving user info" });
  }
};
/**
 * @openapi
 * /auth/refresh-token:
 *   get:
 *     summary: Atualiza o token de autenticação.
 *     description: Este endpoint permite que um usuário atualize seu token de autenticação. O usuário deve fornecer um token de autenticação válido no cabeçalho da solicitação para obter um novo token.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token atualizado com sucesso.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       401:
 *         description: Token de autenticação inválido ou expirado.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Token de autenticação inválido ou expirado."
 *       500:
 *         description: Erro ao gerar token para ID do usuário.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Erro interno ao gerar token de autenticação."
 */
module.exports.refreshToken = (req, res) => {
  const id = req.user.id;
  try {
    const token = jwt.sign({ id }, process.env.SECRET, { expiresIn: 60 * 15});
    logger.info(`Token generated for user ${id}.`);
    return res.json({ token });
  } catch (err) {
    logger.error(`Error generating token for user ${id}: ${err.message}`);
    return res.status(500).json({ message: "Error generating token for user id!" });
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
 *                 message:
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
    const oldUser = await User.findOne({ email });
    
    if (!oldUser) {
      logger.error("User does not exist");
      return res.status(422).json({ message: 'User does not exist' });
    }

    const token = jwt.sign({ id: oldUser.id }, process.env.SECRET, { expiresIn: '15m' });

    const transport = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: process.env.MAIL_PORT,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
      }
    });

    var mailOptions = {
      from: 'youremail@gmail.com',
      to: 'myfriend@yahoo.com',
      subject: 'Reset password',
      text: `http://localhost:5173/reset-password/${token}`
    };
    
    await transport.sendMail(mailOptions);
    logger.info("Password reset email sent successfully");

    return res.status(200).json({ message: 'Email sent to recover password' });
    
  } catch (err) {
    logger.error("Error on forgot password: " + err.message);
    return res.status(500).json({ message: "Error on forgot password, please try again" });
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
      logger.warn(`User with id ${id} not found`);
      return res.status(404).json({ message: 'User not found' });
    }
    logger.info('Successfully reset password for user', { userId: id });
    return res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError) {
      logger.error("Invalid token");
      return res.status(400).json({ message: "Invalid token" });
    }

    logger.error("Cannot reset password, try again.", { error: err.message });
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
    res.clearCookie("refreshToken", { httpOnly: true, secure: true });
    res.clearCookie("token", { httpOnly: true, secure: true });
    // Loga a ação de logout
    logger.info('Logout successful');
    
    // Retorna uma resposta de sucesso
    res.status(200).json({ message: "Logout successful." });
  } catch (error) {
      logger.error(`Logout error: ${error.message}`);
      res.status(500).json({ message: "An error occurred during logout." });
  }
};

