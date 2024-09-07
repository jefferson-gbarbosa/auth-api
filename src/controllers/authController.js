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
 * @openapi
 * /auth/register:
 *   post:
 *     summary: Cadastra um novo usuário.
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
 *     responses:
 *       201:
 *         description: Usuário cadastrado com sucesso.
 *       400:
 *         description: Dados inválidos.
 */
module.exports.register = async (req, res) => {
  const {name, email, password} = req.body;
  // check if user exits
  const userExists = await User.findOne({ email: email });
  if(userExists){
    // return next(new createError('User already exists',400));
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
    res.status(201).json({ user, message:'User registered sucessfully' })
  } catch (err) {
    logger.error("Registration failed.")
    res.status(500).json({message: 'Registration failed.'})
  }
}
/**
 * @openapi
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
 *     responses:
 *       200:
 *         description: Login bem-sucedido.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       401:
 *         description: Credenciais inválidas.
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
      res.cookie('token', token);
      generateRefreshToken(user.id,res);
      logger.info(`User ${user.id} logged in successfully.`);
      return res.json({status: 'success', token});
    } catch (err) {
      logger.error(`Error during login process: ${err.message}`);
      res.status(500).json({message: 'A server error occurred, please try again later!'})
    }
}
/**
 * @openapi
 * /auth/profile:
 *   get:
 *     summary: Retorna as informações do perfil do usuário.
 *     responses:
 *       200:
 *         description: Informações do perfil do usuário.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 email:
 *                   type: string
 *                   example: user@example.com
 *                 name:
 *                   type: string
 *                   example: Nome do Usuário
 *       401:
 *         description: Não autorizado.
 */
module.exports.infoUser = async (req, res) => {
  const id = req.user.id;
  try {
    const user = await User.findById(id);
    logger.info("success")
    return res.json({ status: 'success', name: user.name, email: user.email});
  } catch (err) {
    logger.error(`Error retrieving user info for ID ${id}: ${err.message}`)
    return res.status(500).json({ message: "A server error occurred, please try again later!" });
  }
};
/**
 * @openapi
 * /auth/refresh-token:
 *   post:
 *     summary: Atualiza o token de autenticação.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 example: refresh-token-exemplo
 *     responses:
 *       200:
 *         description: Token atualizado com sucesso.
 *       401:
 *         description: Token inválido.
 */
module.exports.refreshToken = (req, res) => {
  const id = req.user.id;
  try {
    const token = jwt.sign({ id }, process.env.SECRET, { expiresIn: 60 * 15});
    logger.info(`Token generated for user ${id}.`);
    return res.json({ token });
  } catch (err) {
    logger.error(`Error generating token for user ${id}: ${err.message}`);
    return res.status(500).json({ message: "A server error occurred, please try again later!" });
  }
};
/**
 * @openapi
 * /auth/forgot-password:
 *   post:
 *     summary: Recupera a senha do usuário.
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
 *     responses:
 *       200:
 *         description: Email enviado para recuperação de senha.
 *       404:
 *         description: Usuário não encontrado.
 */
module.exports.forgotPassword = async(req, res) =>{
  const { email } = req.body;
  try {
    const oldUser = await User.findOne({ email: email });

    if(!oldUser){
      logger.error("User does not exist")
      return res.status(422).json({
        message: 'User does not exist'
      })
    }
    
    const token = jwt.sign({ id: oldUser.id }, process.env.SECRET, { expiresIn: 60 * 15});

    var transport = nodemailer.createTransport({
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
    
    transport.sendMail(mailOptions, function(error, info){
      if (error) {
        logger.warn("error sending email")
        return res.status(401).json({message: 'error sending email'});
      } else {
        logger.infor("success")
        return res.json({status: 'success', message: 'email sent'});
      }
    });
   
  } catch (err) {
    logger.error("Error on forgot password, try again")
    return res.status(500).json({ message: "Error on forgot password, try again" });
  }
}
/**
 * @openapi
 * /auth/reset-password:
 *   post:
 *     summary: Redefine a senha do usuário.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 example: reset-token
 *               newPassword:
 *                 type: string
 *                 example: novaSenha123
 *     responses:
 *       200:
 *         description: Senha redefinida com sucesso.
 *       400:
 *         description: Token de redefinição inválido ou dados inválidos.
 */
module.exports.resetPassword = async(req, res) => {
  const {token} = req.params;
  const {password} = req.body;
  try {
    const verify = jwt.verify(token, process.env.SECRET)
    const id = verify.id;
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);
    await User.findByIdAndUpdate({_id:id}, { password: passwordHash})
    logger.info('success reset password,')
    return res.json({status: 'success', message:'updated password'})
  } catch (err) {
    logger.error("Cannot reset password, try again.")
    return res.status(500).json({ message: "Cannot reset password, try again." });
  }
};
/**
 * @openapi
 * /auth/logout:
 *   post:
 *     summary: Faz logout do usuário.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 example: exemplo-token
 *     responses:
 *       200:
 *         description: Logout bem-sucedido.
 *       401:
 *         description: Token inválido ou não fornecido.
 */
module.exports.logout = (req, res) => {
  res.clearCookie("refreshToken",{expiresIn: 0});
  logger.info('success')
  res.json({ status: 'success' });
};

