/** @type {import('jest').Config} */
module.exports = {
    testEnvironment: 'node', // Indica que o ambiente de teste é Node.js
    testMatch: [
      "**/__tests__/**/*.js?(x)", // Procura arquivos de teste na pasta __tests__
      "**/?(*.)+(spec|test).js?(x)" // Ou arquivos com sufixos .spec.js ou .test.js
    ],
};

