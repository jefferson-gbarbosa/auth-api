const mongoose = require('mongoose');
// credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.szqhjan.mongodb.net/?retryWrites=true&w=majority`).then(() =>{
    console.log("Connect DB ok");
})
.catch((err) => console.error(err))


