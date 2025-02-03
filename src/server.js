import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import {PORT, FRONT_API_URL} from './config/variables.js'
import rateLimit from 'express-rate-limit'
import AuthRoutes from './routes/AuthRoutes.js'
import { mailer } from './services/emilService.js'

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(cors({
    origin: FRONT_API_URL, // Cambia a la URL de tu frontend
    credentials: true // Permite el envío de cookies
}));

const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 Minuto
    max: 20, // Máximo de 100 peticiones por IP
    handler: (req, res) => {
        res.status(429).json({ error: "Too many requests, please try again later" });
    },
    standardHeaders: true,
    legacyHeaders: false,
});

app.get('/', (req, res) => {
    res.send('Welcome to the API');
});

app.use('/auth', AuthRoutes)

app.post('/api/mailer', mailer)

app.listen(PORT, () => {
    console.log(`Inicie pe en puerto: ${PORT}`)
})