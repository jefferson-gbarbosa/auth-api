const { MailtrapClient } = require("mailtrap");

const TOKEN = process.env.MAILTRAP_TOKEN;

const mailtrapClient = new MailtrapClient({
  token: TOKEN
});

const sender = {
  email: "hello@demomailtrap.com",
  name: "Jefferson Gonçalves",
};

module.exports = { mailtrapClient, sender};
