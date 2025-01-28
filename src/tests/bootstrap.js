const { MongoMemoryServer } = require("mongodb-memory-server");
const mongoose = require("mongoose");
const app = require('../../index'); // Correct path to your app
require('dotenv').config({ path: '.env.test' }); 

let server;
let mongod;

beforeAll(async () => {
    try {
        mongod = await MongoMemoryServer.create();
        const uri = mongod.getUri();
        console.log("Conectando ao MongoDB em memória:", uri);
        await mongoose.connect(uri);
        console.log("Conexão com o MongoDB em memória estabelecida.");

        const PORT = process.env.PORT || 5000; // Use environment variable if available
        server = app.listen(PORT, () => console.log(`Servidor iniciado na porta ${PORT}.`));
    } catch (error) {
        console.error("Erro durante o setup:", error);
        throw error; // Re-throw the error to fail the tests
    }
});

afterAll(async () => {
    try {
        await mongoose.connection.dropDatabase();
        await mongoose.connection.close();
        await mongod.stop();
        await new Promise((resolve, reject) => {
            server.close((err) => {
                if (err) {
                    console.error("Erro ao fechar o servidor:", err);
                    return reject(err);
                }
                console.log("Servidor fechado.");
                resolve();
            });
        });
        console.log("Banco de dados em memória e servidor encerrados.");
    } catch (error) {
        console.error("Erro durante o teardown:", error);
    }
});