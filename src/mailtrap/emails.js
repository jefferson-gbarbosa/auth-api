const { mailtrapClient, sender } = require("./mailtrap.config")
const { PASSWORD_RESET_REQUEST_TEMPLATE,PASSWORD_RESET_SUCCESS_TEMPLATE,VERIFICATION_EMAIL_TEMPLATE, } = require("./emailTemplates")

const sendVerificationEmail = async (email, verificationToken) => {
    const recipient = [{email}]

    try {
		const response = await mailtrapClient.send({
			from: sender,
			to: recipient,
			subject: "Verify your email",
			html: VERIFICATION_EMAIL_TEMPLATE.replace("{verificationCode}", verificationToken),
			category: "Email Verification",
		});

		console.log("Email sent successfully", response);
	} catch (error) {
		console.error(`Error sending verification`, error);

		throw new Error(`Error sending verification email: ${error}`);
	}
}

const sendPasswordResetEmail = async (email, resetURL) => {
    const recipient = [{email}]

    try {
		const response = await mailtrapClient.send({
			from: sender,
			to: recipient,
			subject: "Reset your password",
			html: PASSWORD_RESET_REQUEST_TEMPLATE.replace("{resetURL}", resetURL),
			category: "Password Reset",
		});
	} catch (error) {
		console.error(`Error sending password reset email`, error);

		throw new Error(`Error sending password reset email: ${error}`);
	}
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail };