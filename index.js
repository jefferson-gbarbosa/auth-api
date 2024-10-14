// imports
require('dotenv').config();
const express = require('express')
const { connectdb } = require('./src/database/connectdb');
const cookieParser = require('cookie-parser');
const cors = require('cors')
const helmet = require('helmet');
const logger = require('./src/utils/logger.js')
const morgan = require('morgan');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const authRouter = require('./src/routes/authRoutes.js')
const app = express();

// Swagger definition
const swaggerDefinition = {
    openapi: '3.0.0',
    info: {
        title: 'Auth API',
        version: '1.0.0',
        description: 'API de autenticação com login, cadastro, recuperação de senha e perfil.',
    },
    components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
          },
        },
    },
};

// Options for the swagger docs
const options = {
    swaggerDefinition,
    apis: ['./src/controllers/*.js'],
};

// Initialize swagger-jsdoc
const swaggerSpec = swaggerJsdoc(options);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ["http://localhost:5173"],
    methods: ["GET","POST"],
    credentials: true
}));
app.use(helmet());

app.use(morgan('combined', {
    stream: {
      write: message => logger.info(message.trim())
    }
}));

app.use("/auth",authRouter)

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}/api-docs`);
});