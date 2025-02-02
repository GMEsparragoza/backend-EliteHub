import dotenv from 'dotenv'
dotenv.config()

export const {
    DATABASE_URL = '',
    FRONT_API_URL = '',
    PORT = '',
} = process.env