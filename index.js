// imports
require('dotenv').config();
const express = require('express')
const { connectdb } = require('./src/database/connectdb');
const cookieParser = require('cookie-parser');
const cors = require('cors')
const helmet = require('helmet');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs')
const authRouter = require('./src/routes/authRoutes.js')
const app = express();

const swaggerFile = YAML.load('./swagger.yaml')

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ["http://localhost:5173"],
    methods: ["GET","POST"],
    credentials: true
}));
app.use(helmet());

app.use("/auth",authRouter)

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerFile));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}/api-docs`);
});

module.exports = app