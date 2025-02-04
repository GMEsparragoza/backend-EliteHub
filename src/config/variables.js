import dotenv from 'dotenv'
dotenv.config()

export const {
    DATABASE_URL = '',
    FRONT_API_URL = '',
    PORT = '',
    EMAIL_USER = '',
    EMAIL_PASS = '',
    JWT_SECRET_AUTH = '',
    JWT_SECRET_REFRESH = '',
    JWT_SECRET_2FA = ''
} = process.env