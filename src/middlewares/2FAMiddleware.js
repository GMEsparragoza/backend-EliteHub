import { sendEmail } from '../services/emilService.js'
import { JWT_SECRET_2FA } from '../config/variables.js'
import jwt from 'jsonwebtoken'

function generarCodigoAleatorio() {
    const codigo = Math.floor(100000 + Math.random() * 900000);
    return codigo.toString(); // Devuelve el código como una cadena de texto
}

export const verifyUser2FA = (req, res, user) => {
    return new Promise((resolve, reject) => {
        if (user.two_fa) {
            // Generar un código aleatorio de 6 dígitos
            const code = generarCodigoAleatorio();
            const tokenData = { code, email: user.email }

            const token = jwt.sign(tokenData, JWT_SECRET_2FA, { expiresIn: '15m' });

            res.cookie('2fa_token', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'Lax',
                maxAge: 15 * 60 * 1000 // 15 Minutos
            });

            try {
                const html = `
                    <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #0F172A;">
                        <div style="max-width: 600px; margin: auto; background-color: #1E293B; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                            <h1 style="color: #F8FAFC;">Two-Step Verification Code</h1>
                            <p style="font-size: 16px; color: #94A3B8;">Hello,</p>
                            <p style="font-size: 16px; color: #94A3B8;">A login attempt has been detected on your account. For security reasons, we have enabled two-step verification (2FA). Please enter the following code to continue with your login:</p>
                            <div style="margin: 20px 0; padding: 15px; background-color: #697b94; border-radius: 8px; color: #0F172A; font-size: 24px; font-weight: bold;">
                                ${code}
                            </div>
                            <p style="font-size: 14px; color: #94A3B8;">This code is valid for the next 15 minutes. If you did not attempt to log in, please ignore this email.</p>
                            <p style="margin-top: 20px; font-size: 12px; color: #aaa;">Thank you for trusting us, <br>The EliteHub Team</p>
                        </div>
                    </div>
                `;

                // Usar la función sendEmail
                sendEmail(user.email, 'Two-Step Verification Code', html)
                    .then(info => resolve(info))
                    .catch(error => reject(error));
            } catch (error) {
                reject(error);
            }
        } else {
            resolve();
        }
    });
};