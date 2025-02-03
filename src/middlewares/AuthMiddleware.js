import jwt from 'jsonwebtoken'
import { JWT_SECRET_AUTH, JWT_SECRET_REFRESH } from '../config/variables.js'

export const verifyToken = async (req, res, next) => {
    const authToken = req.cookies ? req.cookies.access_token : null;

    jwt.verify(authToken, JWT_SECRET_AUTH, (err, decoded) => {
        if (err) {
            const refreshToken = req.cookies ? req.cookies.refresh_token : null;
            if (!refreshToken) {
                return res.status(401).json({ message: 'User Not Authenticated' });
            }

            jwt.verify(refreshToken, JWT_SECRET_REFRESH, (err, decodedRefresh) => {
                if (err) {
                    return res.status(401).json({ message: 'Error or invalid Refresh Token', error: err });
                }

                const tokenPayload = {
                    id: decodedRefresh.id,
                    email: decodedRefresh.email,
                    username: decodedRefresh.username,
                };

                // Generate new Access Token
                const newAccessToken = jwt.sign(tokenPayload, JWT_SECRET_AUTH, { expiresIn: '15m' });
                // Optional: Refresh the Refresh Token
                const newRefreshToken = jwt.sign(tokenPayload, JWT_SECRET_REFRESH, { expiresIn: '7d' });

                res.cookie('access_token', newAccessToken, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'Lax',
                    maxAge: 15 * 60 * 1000 // 15 Minutos
                });
                res.cookie('refresh_token', newRefreshToken, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'Lax',
                    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 Dias
                });
                req.user = decodedRefresh; // Optional: Use the refreshed token data
                next();
            })
        } else {
            req.user = decoded;
            next();
        }
    })
}