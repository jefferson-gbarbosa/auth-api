const nodemailer = require('nodemailer');
const sendVerificationEmail = async(token) => {
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
}

module.exports = { sendVerificationEmail }

