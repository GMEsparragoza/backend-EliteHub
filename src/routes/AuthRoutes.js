import express from 'express'
import { body } from 'express-validator'
import { AuthController } from '../controllers/authController.js';
import { verifyToken } from '../middlewares/AuthMiddleware.js';

const router = express.Router();

router.post('/signup', [
    body('email').isEmail().withMessage('You must enter a valid email'),
    body('username').notEmpty().withMessage('You must enter a username'),
    body('password').isStrongPassword({
        minLength: 6,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,  // Añadido para asegurarse de que también se pida un carácter especial
    }).withMessage('The password must be at least 6 characters long and contain uppercase, lowercase, and at least one number.')
], AuthController.signUp)

router.post('/signin', [
    body('email').isEmail().withMessage('You must enter a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], AuthController.signIn)

router.post('/verify-2fa', [
    body('email').isEmail().withMessage('You must enter a valid email'),
    body('code').isLength({ min:6, max:6 }).withMessage('The code must be 6 digits long')
], AuthController.verify2FA)

router.post('/verify-auth', verifyToken, AuthController.auth)

router.post('/logout', AuthController.logOut)

export default router