const { Resend } = require('resend');

// Initialize Resend client
const resend = new Resend(process.env.RESEND_API_KEY);

console.log('📧 Mailer Config: Provider: Resend API (HTTPS)');

/**
 * Sends a verification email to the user using Resend API.
 * @param {string} email - The recipient's email address.
 * @param {string} code - The 6-digit verification code.
 */
async function sendVerificationEmail(email, code) {
    try {
        const { data, error } = await resend.emails.send({
            from: process.env.EMAIL_FROM || 'PhysioSim <onboarding@resend.dev>',
            to: [email],
            subject: "Verify your PhysioSim account",
            html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
          <h2 style="color: #2c3e50;">Verify your email</h2>
          <p>Thank you for registering with PhysioSim. Please use the following code to verify your account:</p>
          <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0;">
            <span style="font-size: 24px; font-weight: bold; letter-spacing: 5px; color: #007bff;">${code}</span>
          </div>
          <p>This code expires in 15 minutes.</p>
          <p style="font-size: 12px; color: #7f8c8d; margin-top: 30px;">If you didn't request this, please ignore this email.</p>
        </div>
      `,
        });

        if (error) {
            console.error("Resend API error:", error);
            return false;
        }

        console.log("Message sent via Resend: %s", data.id);
        return true;
    } catch (error) {
        console.error("Error sending email via Resend:", error);
        return false;
    }
}

module.exports = { sendVerificationEmail };
