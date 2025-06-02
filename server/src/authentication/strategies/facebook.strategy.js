const FacebookStrategy = require('passport-facebook').Strategy;
const db = require('../../../database-mysql/index'); // Adjusted path

const facebookStrategy = new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL || '/auth/facebook/callback',
    profileFields: ['id', 'emails', 'name'] // Request 'id', 'emails', and 'name' fields
}, async (accessToken, refreshToken, profile, done) => {
    const facebookId = profile.id;
    // Facebook returns 'emails' as an array. The first one is typically the primary.
    const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
    // Facebook returns 'name' as an object with 'givenName' and 'familyName'.
    const name = profile.name ? `${profile.name.givenName} ${profile.name.familyName}` : profile.displayName; // Fallback to displayName if name object is not complete

    if (!email) {
        // This can happen if the user's email is not verified on Facebook, or they chose not to share it.
        // It's a common issue with Facebook OAuth.
        // Application might need a way to prompt user for email if this occurs.
        console.warn("Facebook did not provide an email for profile ID:", profile.id);
        return done(new Error("Email not provided by Facebook. Please ensure your Facebook account has a verified, primary email and that you have granted permission to share it."), null);
    }

    try {
        // 1. Find user by facebookId
        const findByFacebookIdQuery = "SELECT * FROM user WHERE facebookId = ?";
        db.query(findByFacebookIdQuery, [facebookId], (err, results) => {
            if (err) {
                console.error("Error querying by facebookId:", err);
                return done(err, null);
            }

            if (results && results.length > 0) {
                return done(null, results[0]); // User found and authenticated via facebookId
            }

            // 2. If not found by facebookId, try to find by email to link account
            const findByEmailQuery = "SELECT * FROM user WHERE email = ?";
            db.query(findByEmailQuery, [email], (err, emailResults) => {
                if (err) {
                    console.error("Error querying by email:", err);
                    return done(err, null);
                }

                if (emailResults && emailResults.length > 0) {
                    // Email exists, user found. Link facebookId to this existing user.
                    const existingUser = emailResults[0];

                    // Check if this email is already associated with a *different* facebookId
                    if (existingUser.facebookId && existingUser.facebookId !== facebookId) {
                        console.warn(`Conflict: Email ${email} already linked to a different Facebook ID.`);
                        return done(null, false, { message: 'This email is already associated with a different Facebook account.' });
                    }

                    // Update the user with the new facebookId and potentially update their name if it wasn't set
                    // COALESCE is used for name to only update it if the new 'name' is not NULL, and keep original if it is.
                    const updateUserQuery = "UPDATE user SET facebookId = ?, name = COALESCE(?, name) WHERE idUser = ?";
                    db.query(updateUserQuery, [facebookId, name, existingUser.idUser], (err, updateResult) => {
                        if (err) {
                            console.error("Error updating user with facebookId:", err);
                            return done(err, null);
                        }
                        existingUser.facebookId = facebookId;
                        if (name) existingUser.name = name; // Update in-memory object as well
                        return done(null, existingUser);
                    });
                } else {
                    // 3. New user: Neither facebookId nor email found. Create a new user.
                    // Password is set to NULL as authentication will be via Facebook.
                    const insertUserQuery = "INSERT INTO user (email, facebookId, name, password) VALUES (?, ?, ?, NULL)";
                    db.query(insertUserQuery, [email, facebookId, name], (err, insertResult) => {
                        if (err) {
                            console.error("Error inserting new user via Facebook:", err);
                            return done(err, null);
                        }
                        const newUser = {
                            idUser: insertResult.insertId,
                            email: email,
                            facebookId: facebookId,
                            name: name
                        };
                        return done(null, newUser);
                    });
                }
            });
        });
    } catch (error) {
        console.error("Unexpected error in FacebookStrategy:", error);
        return done(error, null);
    }
});

module.exports = facebookStrategy;
