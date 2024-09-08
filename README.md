# Api de Autenticação JWT com sistema construído em Node.js, Express e MongoDB Atlas.

Api Node.js e Express com autenticação de usuário utilizando JWT(Json Web Token), Nodemailer para recuperação de senha, MongoDB Atlas para serviços de armazenamento de dados na nuvem.

Em resumo,uma API de autenticação é um conjunto de regras e ferramentas que permite a um sistema verificar a identidade de um usuário ou de uma aplicação. Em outras palavras, é um mecanismo que ajuda a garantir que apenas pessoas ou sistemas autorizados tenham acesso a determinados recursos ou informações.

## Requisitos

### Requisitos funcionais

- [x] Permitir que novos usuários criem uma conta fornecendo informações como nome, e-mail e senha;
- [x] Permitir que usuários existentes se autentiquem fornecendo credenciais válidas (e-mail e senha) para obter um token de acesso;
- [x] Permitir que usuários recuperem ou redefinam suas senhas se esquecerem;
- [x] Permitir que usuários encerrem suas sessões e invalidem tokens de acesso;
- [x] Confirmar a validade do endereço de e-mail fornecido durante o registro.

### Requisitos não-funcionais

- [x] Garantir que todas as operações da API estejam protegidas contra ataques e vulnerabilidades;
- [x] A API deve ser fácil de usar e bem documentada para que desenvolvedores possam integrá-la facilmente;
- [x] O código da API deve ser modular e fácil de manter e atualizar;
- [x] A API deve registrar eventos relevantes para permitir a auditoria e solução de problemas.

## Configurações Iniciais

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

## Instalação

Instale o **nodemon** 

```
npm install nodemon
```

Fazer o clone do repositório

```
git clone https://github.com/jefferson-gbarbosa/auth-api
```

Instalar os pacotes

```
npm install 
```

Rodar o servidor

```
npm start
```

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

#### Autenticando usuário

Para autenticar usuário, crie e utilize a rota ```http://localhost:3000/auth/login``` com método **POST**, especificando **email** e **password**. 

```
{
	"email": "test@gmail.com",
	"password": "test123456"
}
```


#### Esqueci a Senha

Para trocar de senha, um email é enviado ao usuário com **token** para ser adicionado a requisição **reset-password**. Crie e utilize a rota ```http://localhost:3000/auth/forgot-password``` com método **POST** para enviar um link com o token ao email do usuário. Copie o token.

```
{
	"email": "test@gmail.com"
}
```

Crie e utilize a rota ```http://localhost:3000/auth/reset-password/:token``` com método **POST** para trocar a senha do usuário. 

```
{
	"password": "hudson19937416"
}
```

### Informações do Usuário

Para acessar dados do cadastro, como nome e email, o usuário deve utilizar a rota ```http://localhost:3000/auth/profile``` com método **GET**, e com o ID do cadastro, obter os dados do perfil do usuário.

### Para atualizar o token de acesso

Para que o usuário permaneça com acesso depois de um tempo, utilize a rota ```http://localhost:3000/auth/refresh``` com o método **GET** e assim garantir o token de autenticação.

## Para encerrar a sessão

Para ermitir que usuários encerrem suas sessões e invalidem tokens de acesso, utilize a rota ```http://localhost:3000/auth/logout``` com o método **GET**.


## Documentação da API (Swagger)

Para documentação da API, acesse o link: http://localhost:3000/api-docs/
