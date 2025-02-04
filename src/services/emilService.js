import nodemailer from 'nodemailer'
import { EMAIL_USER, EMAIL_PASS } from '../config/variables.js'

const email = EMAIL_USER  // Tu correo de usuario
const pass = EMAIL_PASS;

export const mailer = async (req, res) => {
    const { to, subject, html } = await req.body; // Se recibe el correo, el asunto y el HTML del cuerpo del correo

    try {
        await sendEmail(to, subject, html);
        res.status(201).json({
            message: 'Mail sent successfully'
        });
    } catch (error) {
        res.status(500).json({
            message: 'Error sending mail',
            error: error
        });
    }
}

export const sendEmail = async (to, subject, html) => {
    // Crear el transportador de correo utilizando nodemailer
    const transporter = nodemailer.createTransport({
        port: 465,
        secure: true, // upgrade later with STARTTLS
        service: 'gmail',
        auth: {
            user: email,
            pass,
        },
    });

    try {
        // Enviar el correo
        await transporter.sendMail({
            from: email, // El correo desde el cual se enviará
            to, // El correo al que se enviará
            subject, // El asunto del correo
            html, // El cuerpo del correo en formato HTML
        });

    } catch (error) {
        throw new Error('Error sending email: ' + error.message);
    }
}