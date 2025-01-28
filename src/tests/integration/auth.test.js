const request = require('supertest');
const app = require('../../../index');
const User = require("../../models/User");
const emails = require('../../mailtrap/emails'); 
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config({ path: '.env.test' }); 

jest.mock('../../mailtrap/emails');
// Variáveis de teste
const validName = 'Test User';
const validEmail = 'teste@teste.com';
const validPassword = 'senha123'; 

describe('Auth API', () => {
  beforeEach(async() => {
    jest.clearAllMocks();
    emails.sendVerificationEmail.mockClear();
    await User.deleteMany({});
    await User.create({
        name: validName,
        email: validEmail,
        password: await bcrypt.hash(validPassword, 10), // Senha criptografada
    });
  });
  
  // Teste de signup
  it('Deve registrar um novo usuário com sucesso', async () => {
      const userData = {
          name: 'Teste User',
          email: 'teste@email.com',
          password: 'password123',
      };

      const hashedPassword = await bcrypt.hash(userData.password, 10);
      userData.password = hashedPassword;

      const response = await request(app)
          .post('/auth/signup')
          .send(userData)
          .expect(200);

      expect(response.body.message).toBe('User registered sucessfully');
      expect(response.body.user.name).toBe(userData.name);
      expect(response.body.user.email).toBe(userData.email);
      expect(response.body.user.password).toBeUndefined();

      const user = await User.findOne({ email: userData.email });
      expect(user).not.toBeNull();
      const passwordMatch = await bcrypt.compare(userData.password, user.password);
      expect(passwordMatch).toBe(true);
      expect(user.verificationToken).toBeDefined();
      expect(user.verificationTokenExpiresAt.getTime()).toBeGreaterThan(Date.now());
      expect(emails.sendVerificationEmail).toHaveBeenCalledTimes(1); 
      expect(emails.sendVerificationEmail).toHaveBeenCalledWith(userData.email, expect.any(String)); 
  });

  it('Deve retornar erro 400 se campos obrigatórios estiverem faltando', async () => {
      const userData = {
          name: 'Teste User',
          email: 'teste@email.com',
      };

      const response = await request(app)
          .post('/auth/signup')
          .send(userData)
          .expect(400);

      expect(response.body.message).toBe('Todos os campos são obrigatórios.');
  });

  it('Deve retornar erro 409 se o email já estiver cadastrado', async () => {
      const userData = {
          name: 'Teste User',
          email: 'teste@email.com',
          password: 'password123',
      };

      await request(app).post('/auth/signup').send(userData);

      const response = await request(app)
          .post('/auth/signup')
          .send(userData)
          .expect(409);

      expect(response.body.message).toBe('User already exists');
  });

  it('Deve retornar erro 500 em caso de erro interno do servidor', async () => {
      const userSaveMock = jest.spyOn(User.prototype, 'save').mockImplementation(() => {
          throw new Error('Erro simulado no banco de dados');
      });

      const userData = {
          name: 'Teste User',
          email: 'teste@email.com',
          password: 'password123',
      };

      const response = await request(app)
          .post('/auth/signup')
          .send(userData)
          .expect(500);

      expect(response.body.message).toBe('Registration failed.');

      userSaveMock.mockRestore();
  });

  // Teste de verificação de código
  it('Deve verificar o email com um código válido', async () => {
    const user = new User({
      email: 'test@example.com',
      password: 'password123',
      verificationToken: 'valid_code',
      verificationTokenExpiresAt: Date.now() + 3600000, // Expira em 1 hora
    });
    await user.save();

    const response = await request(app)
      .post('/auth/verify-email')
      .send({ code: 'valid_code' });

    expect(response.statusCode).toBe(200);
    expect(response.body.message).toBe('Email verified successfully');
    expect(response.body.user.isVerified).toBe(true);
    expect(response.body.user.verificationToken).toBeUndefined();
    expect(response.body.user.verificationTokenExpiresAt).toBeUndefined();

    const updatedUser = await User.findById(user._id);
    expect(updatedUser.isVerified).toBe(true);
    expect(updatedUser.verificationToken).toBeUndefined();
    expect(updatedUser.verificationTokenExpiresAt).toBeUndefined();
  });

  it('Deve retornar erro 400 com código inválido', async () => {
    const response = await request(app)
      .post('/auth/verify-email')
      .send({ code: 'invalid_code' });

    expect(response.statusCode).toBe(400);
    expect(response.body.message).toBe('Invalid or expired verification code');
  });

  it('Deve retornar erro 400 com código expirado', async () => {
    const user = new User({
      email: 'test@example.com',
      password: 'password123',
      verificationToken: 'expired_code',
      verificationTokenExpiresAt: Date.now() - 3600000, // Já expirou
    });
    await user.save();

    const response = await request(app)
      .post('/auth/verify-email')
      .send({ code: 'expired_code' });

    expect(response.statusCode).toBe(400);
    expect(response.body.message).toBe('Invalid or expired verification code');
  });

  it('Deve retornar erro 500 em caso de erro no servidor', async () => {
        // Simula um erro no banco de dados, por exemplo, desconectando
        const findOneSpy = jest.spyOn(User, 'findOne').mockImplementationOnce(() => {
            throw new Error("Erro simulado no banco de dados");
        })

        const response = await request(app)
            .post('/auth/verify-email')
            .send({ code: 'any_code' });

        expect(response.statusCode).toBe(500);
        expect(response.body.message).toBe('Server error');

        // Restaura a função original para evitar efeitos colaterais em outros testes
        findOneSpy.mockRestore();
   });
  // Tete de login
  it('deve fazer login com sucesso e retornar um token', async () => {
    const response = await request(app)
        .post('/auth/login')
        .send({
            email: validEmail,
            password: validPassword,
        });

    expect(response.status).toBe(200);
    expect(response.body.message).toBe('logged in successfully');
    expect(response.body.token).toBeDefined(); // Verifica se o token foi retornado
  });

  it('não deve permitir login com email inválido', async () => {
      const response = await request(app)
          .post('/auth/login')
          .send({
              email: 'email_invalido@teste.com',
              password: validPassword,
          });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('User does not exist');
  });

  it('não deve permitir login com senha inválida', async () => {
      const response = await request(app)
          .post('/auth/login')
          .send({
              email: validEmail,
              password: 'senhaErrada',
          });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Incorrect email or password');
  });

  it('deve retornar erro quando email ou senha estiverem ausentes', async () => {
      const response = await request(app)
          .post('/auth/login')
          .send({
              email: validEmail,
          });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Email and password are required');
  });
  //Teste de acesso ao profile
  it('deve retornar informações do usuário com base no cookie de autorização', async () => {
    const user = new User({
      name: 'John Doe',
      email: 'john@example.com',
      password: 'senha123',
    });
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.SECRET);
    const response = await request(app)
      .get('/auth/profile')
      .set('Cookie', `token=${token}`);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ name: 'John Doe', email: user.email });
  });

  it('deve retornar 404 se o usuário não for encontrado', async () => { 
    const response = await request(app)
      .get('/auth/profile')
    expect(response.status).toBe(401);
    expect(response.body.message).toBe('No token provided');
  });
  it('deve retornar 500 em caso de erro interno', async () => {
    const user = { id: '1234', name: 'John Doe' };
    const token = jwt.sign(user, process.env.SECRET);
    const response = await request(app)
      .get('/auth/profile')
      .set('Cookie', `token=${token}`);
    expect(response.status).toBe(500);
    expect(response.body.message).toBe('Error retrieving user info');
  });
  //Teste de Refresh Token
  it('should generate a new token and set it as a cookie', async () => {
    const user = new User({
      name: 'John Doe',
      email: 'john@example.com',
      password: 'senha123',
    });
    await user.save();
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH, { expiresIn: '7d' });
    const response = await request(app)
      .get('/auth/refresh') 
      .set('Cookie', `refreshToken=${refreshToken}`)
      .expect(200);
    expect(response.body.token).toBeDefined();
  });
  it('should return 401 if no refresh token is provided', async () => {
    const response = await request(app)
      .get('/auth/refresh')
      .expect(401); 
    
    expect(response.body.message).toBe('No token found');
  });
  it('should return 403 if the refresh token is invalid', async () => {
    const invalidToken = 'invalid_token';  
    const response = await request(app)
      .get('/auth/refresh')
      .set('Cookie', `refreshToken=${invalidToken}`)  
      .expect(403);  
    expect(response.body.message).toBe('Invalid or expired token');
  });
  //Teste de forgot password
  it('should send a password reset link if user exists', async () => {
    // Criar um usuário de teste
    const user = new User({
      name: 'John Doe',
      email: 'john@example.com',
      password: 'senha123',
    });
    await user.save();

    const response = await request(app)
      .post('/auth//forgot-password')
      .send({ email: 'john@example.com' });

    expect(response.status).toBe(200);
    expect(response.body.message).toBe('Password reset link sent to your email');
  });
  it('should return error if user does not exist', async () => {
    const response = await request(app)
      .post('/auth//forgot-password')
      .send({ email: 'nonexistent@example.com' });

    expect(response.status).toBe(422);
    expect(response.body.message).toBe('User not found');
  });
  // Teste de reset password
  it('deve resetar a senha com um token válido', async () => {
    const user = new User({
      name: 'John Doe',
      email: 'john@example.com',
      password: 'senha123',
    });
    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiresAt = Date.now() + 1 * 60 * 60 * 1000;

    user.resetPasswordToken = resetToken;
		user.resetPasswordExpiresAt = resetTokenExpiresAt;
    await user.save();
  
    const response = await request(app)
      .post(`/auth/reset-password/${resetToken}`)
      .send({ password: 'newpassword' });

    // Verificar se a resposta tem sucesso
    expect(response.status).toBe(200);
    expect(response.body.message).toBe('Password reset successful');

    // Verificar se a senha foi realmente alterada no banco de dados
    const updatedUser = await User.findOne({ email: user.email });
    expect(updatedUser.password).not.toBe('senha123');
  });
  it('não deve resetar a senha com um token inválido', async () => {
    const invalidToken = 'invalid-token'
    const response = await request(app)
      .post(`/auth/reset-password/${invalidToken}`)
      .send({ password: 'newpassword' });
    expect(response.status).toBe(400);
    expect(response.body.message).toBe('Token is invalid or expired');
  });
  it('não deve resetar a senha se o token estiver expirado', async () => {
    const user = new User({
      name: 'John Doe',
      email: 'john@example.com',
      password: 'senha123',
    });
    await user.save();
    const expiredToken = jwt.sign({ id: user.id }, process.env.SECRET, {
      expiresIn: -3600,  
    });
    const response = await request(app)
      .post(`/auth/reset-password/${expiredToken}`)
      .send({ password: 'newpassword' });
    expect(response.status).toBe(400);
    expect(response.body.message).toBe('Token is invalid or expired');
  });
  // Teste de logout
  it('should logout the user and clear cookies', async () => {
    const response = await request(app)
      .get('/auth/logout');

    expect(response.status).toBe(200);
    expect(response.body.message).toBe('Logout successful.');
  });
})
