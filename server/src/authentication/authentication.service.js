const jwt = require("jsonwebtoken");
const db = require("../../database-mysql/index"); // Assuming db is exported from here
const bcrypt = require("bcrypt"); // For hashing tokens

const generateToken = (user, secret, expiresIn) => {
    const token = jwt.sign({ user }, secret, { expiresIn });
    return token;
};

const generateAccessToken = (user) => {
    return generateToken(user, process.env.JWT_SECRET, process.env.JWT_EXPIRY || '15m');
};

const generateRefreshToken = (user) => {
    return generateToken(user, process.env.REFRESH_TOKEN_SECRET, process.env.REFRESH_TOKEN_EXPIRY || '7d');
};

// --- Refresh Token Database Operations ---

const storeRefreshToken = async (userId, token, expiresAt) => {
    const saltRounds = 10; // Or use a value from .env
    const hashedToken = await bcrypt.hash(token, saltRounds);
    const query = 'INSERT INTO user_refresh_tokens (userId, token, expiresAt, createdAt) VALUES (?, ?, ?, NOW())';
    try {
        const [results] = await db.promise().query(query, [userId, hashedToken, expiresAt]);
        return results.insertId;
    } catch (error) {
        console.error("Error storing refresh token:", error);
        throw error; // Re-throw to be handled by controller
    }
};

const validateRefreshToken = async (userId, token) => {
    const query = 'SELECT token, expiresAt FROM user_refresh_tokens WHERE userId = ? AND expiresAt > NOW() ORDER BY createdAt DESC';
    try {
        const [rows] = await db.promise().query(query, [userId]);
        if (rows.length === 0) {
            return false; // No active tokens for user
        }
        // Iterate through tokens in case user has multiple (though typically we'd use the latest)
        for (const row of rows) {
            const isValid = await bcrypt.compare(token, row.token);
            if (isValid) {
                return true; // Found a valid token
            }
        }
        return false; // No matching valid token found
    } catch (error) {
        console.error("Error validating refresh token:", error);
        throw error;
    }
};

const deleteRefreshToken = async (userId, token) => {
    // This is a bit more complex with hashed tokens. We need to find the specific token to delete.
    // A simpler approach if not rotating or if tokens are unique per device:
    // const query = 'DELETE FROM user_refresh_tokens WHERE userId = ? AND token = ?';
    // However, since we hash, we'd need to retrieve all, compare, then delete by ID.
    // For simplicity here, if a user logs out, we might delete all their tokens,
    // or require a 'deviceId' if we want to delete a specific one.
    // Let's assume for now we delete all tokens for the user upon logout for simplicity,
    // or if a specific token is compromised.
    // If we need to delete a specific token, we'd need to retrieve them, compare, then delete by ID.
    // This simplified version deletes all tokens for the user if any single token is used for logout.
    // This is not ideal for "delete specific token" if multiple devices are logged in.

    // To implement precise deletion of THE USED token (if hashed):
    // 1. Get all tokens for user.
    // 2. bcrypt.compare the provided token against each stored hashed token.
    // 3. If a match is found, delete that specific row by its ID.
    // This is more complex than a simple DELETE WHERE token = ?.
    // For this example, we'll keep it simple and delete all tokens for that user as a placeholder.
    // A more robust solution would involve a unique identifier for each token if specific deletion is needed.

    // Placeholder for finding the exact token to delete:
    // This requires fetching tokens, comparing, then deleting by ID.
    // For now, this function will be a bit conceptual for deleting a single *specific* hashed token.
    // A common strategy upon logout is to delete the *specific* token that was sent.
    // We'll simulate this by finding it.

    const getTokensQuery = 'SELECT id, token FROM user_refresh_tokens WHERE userId = ? AND expiresAt > NOW()';
    try {
        const [rows] = await db.promise().query(getTokensQuery, [userId]);
        for (const row of rows) {
            const matches = await bcrypt.compare(token, row.token);
            if (matches) {
                const deleteQuery = 'DELETE FROM user_refresh_tokens WHERE id = ?';
                await db.promise().query(deleteQuery, [row.id]);
                return true; // Token found and deleted
            }
        }
        return false; // Token not found
    } catch (error) {
        console.error("Error deleting refresh token:", error);
        throw error;
    }
};

const deleteAllRefreshTokensForUser = async (userId) => {
    const query = 'DELETE FROM user_refresh_tokens WHERE userId = ?';
    try {
        await db.promise().query(query, [userId]);
        return true;
    } catch (error) {
        console.error("Error deleting all refresh tokens for user:", error);
        throw error;
    }
};


module.exports = {
    generateToken,
    generateAccessToken,
    generateRefreshToken,
    storeRefreshToken,
    validateRefreshToken,
    deleteRefreshToken,
    deleteAllRefreshTokensForUser
};