const nodemailer = require('nodemailer');

// Build transporter configuration
const transportConfig = {};

// Option 1: Use EMAIL_SERVICE for simplified configuration (e.g., 'gmail', 'outlook')
if (process.env.EMAIL_SERVICE) {
  transportConfig.service = process.env.EMAIL_SERVICE;
  transportConfig.auth = {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  };
} else {
  // Option 2: Manual host/port configuration
  transportConfig.host = process.env.EMAIL_HOST;
  transportConfig.port = process.env.EMAIL_PORT;
  transportConfig.secure = process.env.EMAIL_PORT == 465; // true for 465, false for other ports
  transportConfig.auth = {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  };
}

const transporter = nodemailer.createTransport(transportConfig);

// Log configuration (masking password for security)
const configLog = {
  service: transportConfig.service || 'N/A',
  host: transportConfig.host || 'N/A',
  port: transportConfig.port || 'N/A',
  secure: transportConfig.secure || false,
  user: transportConfig.auth?.user || 'N/A',
};
console.log('📧 Mailer Config:', JSON.stringify(configLog));

// Verify connection on startup (non-blocking)
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Mailer connection error:', error.message);
    console.error('   Code:', error.code);
    if (error.code === 'ETIMEDOUT') {
      console.error('   ⚠️  SMTP port may be blocked by Railway. Consider switching to Resend API.');
    }
  } else {
    console.log('✅ Mailer is ready to take our messages');
  }
});

/**
 * Sends a verification email to the user.
 * @param {string} email - The recipient's email address.
 * @param {string} code - The 6-digit verification code.
 */
async function sendVerificationEmail(email, code) {
  try {
    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM || '"PhysioSim" <no-reply@physiosim.com>',
      to: email,
      subject: "Verify your PhysioSim account",
      text: `Your verification code is: ${code}\n\nThis code expires in 15 minutes.`,
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
    console.log("Message sent: %s", info.messageId);
    return true;
  } catch (error) {
    console.error("Error sending email:", error);
    return false;
  }
}

module.exports = { sendVerificationEmail };
