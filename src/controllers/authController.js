import { validationResult } from 'express-validator'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { JWT_SECRET_AUTH, JWT_SECRET_REFRESH, JWT_SECRET_2FA } from '../config/variables.js'
import { createNewUser, getUserByEmail, getUserByUsername, getUserByID } from '../models/users.js';
import {verifyUser2FA} from '../middlewares/2FAMiddleware.js'

const signUp = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    const { username, email, password } = req.body;
    try {
        const existingEmail = await getUserByEmail(email);
        if (existingEmail) {
            return res.status(400).json({ message: 'Mail is already in use' })
        }
        const existingUsername = await getUserByUsername(username);
        if (existingUsername) {
            return res.status(400).json({ message: 'The username is already in use' })
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const result = await createNewUser(email, username, hashedPassword);

        res.status(201).json({
            message: "User Created Successfully",
            user: result
        })
    } catch (error) {
        res.status(500).json({ message: 'Server Error' })
    }
}

const signIn = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    const { email, password } = req.body;
    try {
        const user = await getUserByEmail(email);
        if (!user) {
            return res.status(400).json({ message: 'Email is not registered' });
        }
        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
            return res.status(400).json({ message: 'Incorrect password' });
        }
        // Verificar si el usuario tiene habilitada la verificación en dos pasos
        if (user.two_fa) {
            // Invocar el middleware de 2FA
            return verifyUser2FA(req, res, user)
                .then(() => {
                    res.send({ message: 'A verification code was sent to the email', twoFARequired: true });
                })
                .catch((error) => {
                    res.status(500).json({ message: 'Error sending verification code', error });
                });
        }

        const tokenPayload = {
            id: user.id,
            email: user.email,
            username: user.username,
        };

        const token = jwt.sign(tokenPayload, JWT_SECRET_AUTH, { expiresIn: '15m' });
        const refreshToken = jwt.sign(tokenPayload, JWT_SECRET_REFRESH, { expiresIn: '7d' });

        res.cookie('access_token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax',
            maxAge: 15 * 60 * 1000 // 15 Minutos
        });
        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 Dias
        });
        res.status(201).json({ message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
}

const verify2FA = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    const { code, email } = req.body;
    const twoFAtoken = req.cookies['2fa_token'];
    if (!twoFAtoken) {
        return res.status(400).send({ message: 'The two-step verification code has expired' });
    }

    try {
        const decoded = jwt.verify(twoFAtoken, JWT_SECRET_2FA);
        if(decoded.email != email){
            return res.status(403).send({ message: 'The email sent from the client was not correct' });
        }
        if (decoded.code != code) {
            return res.status(400).send({ message: 'Invalid 2FA code.' });
        }
        const user = await getUserByEmail(email);
        if (!user) {
            return res.status(404).send({ message: 'User not found.' });
        }

        const tokenPayload = {
            id: user.id,
            email: user.email,
            username: user.username,
        };
        const sessionToken = jwt.sign(tokenPayload, JWT_SECRET_AUTH, { expiresIn: '15m' });
        const refreshToken = jwt.sign(tokenPayload, JWT_SECRET_REFRESH, { expiresIn: '7d' });

        res.cookie('access_token', sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax',
            maxAge: 15 * 60 * 1000 // 15 Minutos
        });
        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 Dias
        });
        // Limpiar la cookie del token de 2FA
        res.clearCookie('2fa_token', {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax'
        });

        res.status(201).json({ message: '2FA verification successful, session started.' });
    } catch (error) {
        return res.status(400).send({ message: 'Invalid or expired 2FA token.', error });
    }
}

const auth = async (req, res) => {
    const tokenUser = req.user;
    try {
        if (!tokenUser) {
            return res.status(401).json({ message: 'You are not authenticated' });
        }
        const user = await getUserByID(tokenUser.id)
        if(!user){
            return res.status(400).json({ message: 'User not found' });
        }

        const userData = {
            username: user.username,
            email: user.email,
            verified: user.verified,
            two_fa: user.two_fa
        }

        res.status(200).json({ message: 'User Autenticated', user: userData })
    } catch (err) {
        res.status(500).json({ message: 'Error getting user data', error: err });
    }
}

export const AuthController = {
    signUp,
    signIn,
    verify2FA,
    auth
}