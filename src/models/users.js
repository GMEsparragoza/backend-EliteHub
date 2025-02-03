import pool from '../config/database.js'

export const createNewUser = async(email, username, password) => {
    try {
        const result = await pool.query(
            `INSERT INTO users (username, email, password)
                VALUES ($1, $2, $3)
                RETURNING id, username, email`,
            [username, email, password]
        );
        return result.rows[0];
    } catch (error) {
        throw new Error('Error creating user: ' + error.message);
    }
}

export const getUserByEmail = async (email) => {
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );
        return result.rows[0];
    } catch (error) {
        throw new Error('Error getting user by Email: ' + error.message);
    }
}

export const getUserByUsername = async (username) => {
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );
        return result.rows[0];
    } catch (error) {
        throw new Error('Error getting user by Username: ' + error.message);
    }
}

export const getUserByID = async (id) => {
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE id = $1',
            [id]
        );
        return result.rows[0];  // Devuelve el primer usuario encontrado
    } catch (error) {
        throw new Error('Error al obtener el usuario: ' + error.message);
    }
};