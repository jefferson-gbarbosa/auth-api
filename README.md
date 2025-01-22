# API de Autenticação JWT com Node.js, Express e MongoDB Atlas.

Esta API oferece autenticação de usuário utilizando JWT (JSON Web Token), Nodemailer para recuperação de senha e MongoDB Atlas como serviço de armazenamento de dados na nuvem.

A API fornece funcionalidades essenciais para gerenciar usuários, incluindo registro, login, recuperação de senha, verificação de e-mail e logout, usando JSON Web Tokens (JWT) para autenticação. A aplicação usa MongoDB Atlas para armazenar os dados dos usuários de forma segura na nuvem e Nodemailer para enviar e-mails, como no processo de recuperação de senha.

## Requisitos

- [x] Registro de Usuário: Criação de novo usuário com envio de e-mail de verificação;
- [x] Login de Usuário: Geração de tokens JWT para autenticação;
- [x] Verificação de E-mail: Confirmação do e-mail do usuário via código de verificação;
- [x] Recuperação de Senha: Envio de link para recuperação de senha por e-mail;
- [x] Alteração de Senha: Mudança de senha com segurança após verificação do token;
- [x] Logout: Revogação do token de autenticação ao sair;
- [x] Obter Informações do Usuário: Acesso a informações básicas do usuário autenticado.

## Tecnologias Utilizadas

- [x] Node.js: Ambiente de execução JavaScript;
- [x] Express: Framework para construção da API;
- [x] MongoDB Atlas: Banco de dados NoSQL na nuvem para persistência de dados;
- [x] JWT (JSON Web Token): Para autenticação e autorização;
- [x] Nodemailer: Para envio de e-mails;
- [x] bcrypt: Para criptografia de senhas.


## Pré-Requisitos

- [x] Node.js;
- [x] MongoDB Atlas (ou MongoDB local, se preferir);
- [x] Nodemailer configurado para envio de e-mails.

## Instalação

Fazer o clone do repositório

```
git clone https://github.com/jefferson-gbarbosa/auth-api
```

Instalar os pacotes

```
npm install 
```
Instale o **nodemon** 

```
npm install nodemon
```

Rodar o servidor

```
npm start
```

## Configurações

Antes de tudo, é preciso saber. Em **Instalação**, logo após clonar o repositório, é preciso configurar a estrutura do arquivo **mail.json** com as credenciais **SMTP** do seu provedor de email. O arquivo está localizado na pasta **config**. No projeto foi utilizado a ferramenta [Mailtrap](https://mailtrap.io/) para testar o envio de email.

```
{
  "host": "smtp.domain.io",
  "port": 2525,
  "secure": false,
  "user": "username@domain.com",
  "pass": "password"
}
```

Depois, é preciso criar um **Cluster** no [MongoDB Atlas](https://www.mongodb.com/cloud/atlas). Crie um conta, clique em **Build my first cluster** e deixe a configuração padrão. Clique em **Create Cluster**. Logo após, clique em **CONNECT** para criar um conexão com o banco de dados, clique em **Add a Different IP Address** e digite o seguinte ip **0.0.0.0/0** que permite o acesso ao seu banco de dados de qualquer lugar, depois clique em __Add IP Address__. Na mesma página crie um **username** e **password** do banco de dados, anote as credenciais. Clique em **Create MongoDB User** e, em seguida, clique em **Choose a connection method**, escolha a opção **Connect your application**, selecione o driver **Node.js** e copie a string de conexão na parte inferior de **Connection String Only**. Clique em **Close**. 

Por fim, configure as variáveis de ambiente no arquivo **.env** na raíz do projeto. Cole a string de conexão no valor a ser recebido na variável **mongodb_url**. Substitua **<password>** pela senha do usuário do banco de dados. Troque o nome do banco de dados **test** por um de sua preferência. Na variável **jwt_key**, crie uma chave secreta para criar o **token de autenticação**. Exemplo de chave secreta ```jw6s5hi53s97dhs07dhsk4vc0a6```. A variável **port** manterá o número de porta que o aplicativo estará em execucão.

```
module.exports = {
  mongodb_url: 'mongodb+srv://username:<password>@cluster0-3etgl.mongodb.net/test?retryWrites=true&w=majority',
  jwt_key: '<chave_secreta>',
  port: 4000
}
```

Crie um arquivo **.env** na raiz do projeto e adicione as seguintes variáveis:

```
MONGO_URI=mongodb+srv://<seu-usuario>:<sua-senha>@cluster0.mongodb.net/nome-do-banco?retryWrites=true&w=majority
JWT_SECRET=seu-segredo-jwt
JWT_EXPIRES_IN=1d
SMTP_HOST=smtp.seuprovedor.com
SMTP_PORT=587
SMTP_USER=seu-email@dominio.com
SMTP_PASS=sua-senha
CLIENT_URL=http://localhost:5173

```
- MONGO_URI: A URL de conexão com o MongoDB Atlas.
- JWT_SECRET: Chave secreta para assinar os tokens JWT.
- SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS: Configurações do servidor SMTP para envio de e-mails (pode ser Gmail ou outro provedor).
- CLIENT_URL: A URL do seu cliente front-end (caso utilize um).

## Testando API

Utilize o [Insomnia](https://insomnia.rest/), [Postman](https://www.postman.com/), ou uma extensão do VS Code (REST client) para testar a API.

#### Criando usuário

Para criar um usuário, crie e utilize a rota ```http://localhost:3000/auth/register``` com método **POST**, especificando **name**, **email** e **password**.

```
{
	"name": "test",
	"email": "test@gmail.com",
	"password": "test123456"
}
```

#### Verificação de E-mail

Esta rota permite que o usuário verifique seu e-mail após o registro. O código de verificação é enviado por e-mail ao usuário, e ele deve enviar esse código de volta para confirmar o endereço de e-mail.

```
{
	"code": "123456"
}
```


#### Autenticando usuário

Para autenticar usuário, crie e utilize a rota ```http://localhost:3000/auth/login``` com método **POST**, especificando **email** e **password**. 

```
{
	"email": "test@gmail.com",
	"password": "test123456"
}
```

#### Esqueci a Senha
Esta rota ```http://localhost:3000/auth/forgot-password``` ,com método **POST**, permite que um usuário solicite um link de redefinição de senha. O usuário deve fornecer o endereço de e-mail associado à sua conta, e a API enviará um link de redefinição de senha para o e-mail fornecido.

```
{
	"email": "test@gmail.com"
}
```


A rota ```http://localhost:3000/auth/reset-password/:token``` com método **POST** permite que o usuário redefina sua senha utilizando um token de redefinição que foi gerado previamente e enviado ao e-mail do usuário.

```
{
	"password": "nova_senha123"
}
```

### Informações do Usuário

Esta rota ```http://localhost:3000/auth/profile``` com método **GET**, retorna as informações básicas do usuário autenticado, incluindo nome e e-mail. O usuário deve estar autenticado para acessar essa rota.


- **Authorization**: O token JWT do usuário deve ser enviado no cabeçalho da requisição.

Exemplo de cabeçalho de requisição:

```http
Authorization: Bearer {token_jwt_aqui}
```

## Para encerrar a sessão
Esta rota ```http://localhost:3000/auth/logout``` com o método **GET**, permite que o usuário faça o logout, limpando o refresh token do cookie e efetivamente encerrando a sessão do usuário.

Se o logout for bem-sucedido, a resposta será:

```json
{
  "success": true,
  "message": "Logout successful."
}

```
### Refresh Token (Atualização do Token)

Esta rota permite que o cliente obtenha um novo token de acesso sem precisar fornecer as credenciais (email e senha) novamente. Isso é importante para manter a sessão do usuário ativa por um período mais longo, sem comprometer a segurança.

A rota utilizada é `http://localhost:3000/auth/refresh-token` com método **GET**.

**Pré-requisitos:**

*   O usuário deve possuir um token válido (que ainda não expirou). Este token é normalmente armazenado em um cookie `httpOnly` (como demonstrado na seção "Autenticando usuário").

**Como Funciona:**

1.  O cliente envia uma requisição **GET** para `/auth/refresh-token`. O cookie `token` (contendo o JWT atual) é automaticamente enviado no cabeçalho da requisição pelo navegador.
2.  O servidor verifica a validade do token presente no cookie.
3.  Se o token for válido (e não expirou), o servidor gera um novo token de acesso e o envia de volta para o cliente, também definindo-o em um cookie `httpOnly`.
4.  Se o token for inválido ou ausente, o servidor retorna um erro (ex: código de status 401 Unauthorized).

**Exemplo de Requisição (GET /auth/refresh-token):**

(Nenhum corpo de requisição é necessário, pois o token é enviado no cookie)

**Exemplo de Resposta Bem-Sucedida (Status 200 OK):**

```json
{
    "token": "novo_token_jwt_aqui"
}
```

## Documentação da API (Swagger)

Para documentação da API, acesse o link: https://auth-api-eb0f.onrender.com/api-docs/
