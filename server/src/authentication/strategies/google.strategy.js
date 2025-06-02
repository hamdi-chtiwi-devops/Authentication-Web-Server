const GoogleStrategy = require('passport-google-oauth20').Strategy;
const db = require('../../../database-mysql/index'); // Adjusted path
// Assuming user service functions might not be directly used here based on subtask description,
// but direct DB interaction is shown. If services were used, they'd be imported.

const googleStrategy = new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
    scope: ['profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    const googleId = profile.id;
    // Google often returns multiple email objects; the primary one is usually the first.
    const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
    const displayName = profile.displayName; // For potential use in 'name' field

    if (!email) {
        // This case should be rare if 'email' scope is granted.
        return done(new Error("Email not provided by Google. Please ensure Google account has a primary email."), null);
    }

    try {
        // 1. Find user by googleId
        const findByGoogleIdQuery = "SELECT * FROM user WHERE googleId = ?";
        db.query(findByGoogleIdQuery, [googleId], (err, results) => {
            if (err) {
                console.error("Error querying by googleId:", err);
                return done(err, null);
            }

            if (results && results.length > 0) {
                return done(null, results[0]); // User found and authenticated via googleId
            }

            // 2. If not found by googleId, try to find by email to link account
            const findByEmailQuery = "SELECT * FROM user WHERE email = ?";
            db.query(findByEmailQuery, [email], (err, emailResults) => {
                if (err) {
                    console.error("Error querying by email:", err);
                    return done(err, null);
                }

                if (emailResults && emailResults.length > 0) {
                    // Email exists, user found. Link googleId to this existing user.
                    const existingUser = emailResults[0];

                    // Check if this email is already associated with a *different* googleId
                    if (existingUser.googleId && existingUser.googleId !== googleId) {
                        console.warn(`Conflict: Email ${email} already linked to a different Google ID.`);
                        // TODO: This is an account collision.
                        // Potentially, inform user: "This email is registered, but with a different Google account."
                        // Or, if local login exists: "Log in with your password to link this Google account."
                        return done(null, false, { message: 'This email is already associated with another Google account.' });
                    }

                    // If googleId field is empty or matches, proceed to link/update
                    const updateUserQuery = "UPDATE user SET googleId = ? WHERE idUser = ?";
                    db.query(updateUserQuery, [googleId, existingUser.idUser], (err, updateResult) => {
                        if (err) {
                            console.error("Error updating user with googleId:", err);
                            return done(err, null);
                        }
                        // Update the user object in memory before passing to done
                        existingUser.googleId = googleId;
                        return done(null, existingUser);
                    });
                } else {
                    // 3. New user: Neither googleId nor email found. Create a new user.
                    // Consider also using profile.displayName for a 'name' field if your table has one.
                    // For password, it's set to NULL as authentication will be via Google.
                    // Ensure 'name' column exists if you add it. For now, only email and googleId.
                    const insertUserQuery = "INSERT INTO user (email, googleId, password, name) VALUES (?, ?, NULL, ?)";
                    db.query(insertUserQuery, [email, googleId, displayName], (err, insertResult) => {
                        if (err) {
                            console.error("Error inserting new user:", err);
                            return done(err, null);
                        }
                        const newUser = {
                            idUser: insertResult.insertId,
                            email: email,
                            googleId: googleId,
                            name: displayName
                            // any other default fields
                        };
                        return done(null, newUser);
                    });
                }
            });
        });
    } catch (error) {
        console.error("Unexpected error in GoogleStrategy:", error);
        return done(error, null);
    }
});

module.exports = googleStrategy;
