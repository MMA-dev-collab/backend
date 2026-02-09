const { Resend } = require('resend');

// Initialize Resend client
let resend;
if (process.env.RESEND_API_KEY) {
  try {
    resend = new Resend(process.env.RESEND_API_KEY);
    console.log('📧 Mailer Config: Provider: Resend API (HTTPS)');
  } catch (e) {
    console.warn('⚠️ Mailer Warning: Failed to initialize Resend:', e.message);
  }
} else {
  console.warn('⚠️ Mailer Warning: RESEND_API_KEY is missing. Email sending will be disabled.');
}

/**
 * Sends a verification email to the user using Resend API.
 * @param {string} email - The recipient's email address.
 * @param {string} code - The 6-digit verification code.
 */
async function sendVerificationEmail(email, code) {
  if (!resend) {
    console.log(`[DEV MODE] Email suppression: Verification code for ${email} is ${code}`);
    return true; // Simulate success in dev/no-key mode
  }

  try {
    const { data, error } = await resend.emails.send({
      from: process.env.EMAIL_FROM || 'PhysioSim <onboarding@resend.dev>',
      to: [email],
      subject: "Verify your PhysioSim account",
      html: `

<div style="margin: 0; padding: 0; background-color: #f8fafc; font-family: 'Inter', Arial, sans-serif;">
    
    <!-- Main Container -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f8fafc; padding: 40px 20px;">
        <tr>
            <td align="center">
                
                <!-- Email Card -->
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 20px; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05); overflow: hidden;">
                    
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); padding: 40px 30px; text-align: center;">
                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                <tr>
                                    <td>
                                        <h1 style="color: white; font-size: 28px; font-weight: 700; margin: 0 0 10px 0; letter-spacing: -0.5px;">
                                            PhysioSim
                                        </h1>
                                        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; margin: 0; font-weight: 400;">
                                            Medical Simulation Platform
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 50px 40px;">
                            
                            <!-- Welcome Icon -->
                            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 30px;">
                                <tr>
                                    <td align="center">
                                        <div style="width: 200px; height: 200px; background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto;">
                                            <img alt="TestNew" src="https://res.cloudinary.com/dhicz31vg/image/upload/v1770662884/WhatsApp_Image_2026-02-07_at_12.41.01_AM_x6qg6l.jpg">
                                        </div>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Title -->
                            <h2 style="color: #1e293b; font-size: 28px; font-weight: 700; text-align: center; margin: 0 0 15px 0;">
                                Verify Your Email Address
                            </h2>
                            
                            <!-- Welcome Message -->
                            <p style="color: #64748b; font-size: 16px; line-height: 1.6; text-align: center; margin: 0 0 30px 0;">
                                Welcome to PhysioSim! Please verify your email address to complete your registration and start using our medical simulation platform.
                            </p>
                            
                            <!-- Verification Code Box -->
                            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin: 40px 0;">
                                <tr>
                                    <td align="center">
                                        <div style="background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); border-radius: 16px; padding: 30px; border: 1px solid #e2e8f0;">

                                            <p style="color: #475569; font-size: 14px; font-weight: 600; margin: 0 0 15px 0; text-transform: uppercase; letter-spacing: 1px;">
                                                Your Verification Code
                                            </p>
                                            <div style="font-size: 42px; font-weight: 700; letter-spacing: 10px; color: #3b82f6; text-align: center; margin: 15px 0; font-family: 'Courier New', monospace;">
                                                ${code}
                                            </div>
                                            <p style="color: #94a3b8; font-size: 14px; margin: 15px 0 0 0;">
                                                Expires in 15 minutes
                                            </p>
                                        </div>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Instructions -->
                            <p style="color: #64748b; font-size: 15px; line-height: 1.6; text-align: center; margin: 0 0 40px 0;">
                                Enter this 6-digit code in the verification screen to confirm your email address and activate your account.
                            </p>
                            
                            <!-- CTA Button -->
                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                <tr>
                                    <td align="center">
                                        <a href="https://physiosim-production.up.railway.app/verify-email" style="background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: white; text-decoration: none; padding: 16px 40px; border-radius: 12px; font-weight: 600; font-size: 16px; display: inline-block; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.25);">
                                            Go to Verification Page
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #f8fafc; padding: 30px 40px; border-top: 1px solid #e2e8f0;">
                            
                            <!-- Security Note -->
                            <p style="color: #94a3b8; font-size: 12px; line-height: 1.5; text-align: center; margin: 0 0 20px 0;">
                                <strong>Security Tip:</strong> This code was sent to you because someone attempted to register with your email. If this wasn't you, please ignore this email.
                            </p>
                            
                            <!-- Contact Info -->
                            <p style="color: #94a3b8; font-size: 12px; line-height: 1.5; text-align: center; margin: 0 0 10px 0;">
                                Need help? Contact our support team at 
                                <a href="mailto:support@physiosim.com" style="color: #6366f1; text-decoration: none;">support@physiosim.com</a>
                            </p>
                            
                            <!-- Copyright -->
                            <p style="color: #cbd5e1; font-size: 12px; text-align: center; margin: 20px 0 0 0;">
                                © 2024 PhysioSim. All rights reserved.
                            </p>
                            
                        </td>
                    </tr>
                    
                </table>
                <!-- End Email Card -->
                
                <!-- Bottom Spacing -->
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top: 30px;">
                    <tr>
                        <td align="center">
                            <p style="color: #94a3b8; font-size: 12px; text-align: center;">
                                This email was sent to you as part of your PhysioSim registration.
                            </p>
                        </td>
                    </tr>
                </table>
                
            </td>
        </tr>
    </table>
    
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
