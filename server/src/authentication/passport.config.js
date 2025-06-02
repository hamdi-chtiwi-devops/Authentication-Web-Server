const passport = require('passport');
const GoogleStrategy = require('./strategies/google.strategy');
const FacebookStrategy = require('./strategies/facebook.strategy');
const db = require('../../database-mysql/index');

// Tell Passport to use the configured strategies
passport.use(GoogleStrategy);
passport.use(FacebookStrategy);

// serializeUser determines which data of the user object should be stored in the session.
// This is called after the `done(null, user)` in the strategy's verify callback.
// We store the user's unique ID.
passport.serializeUser((user, done) => {
    // Assuming 'user' object has 'idUser' property based on strategy implementation
    if (!user || typeof user.idUser === 'undefined') {
        return done(new Error('User object or user.idUser is undefined in serializeUser'), null);
    }
    done(null, user.idUser);
});

// deserializeUser is used to retrieve the full user object from the session using the ID stored by serializeUser.
// This user object is then attached to `req.user`.
passport.deserializeUser((id, done) => {
    const query = "SELECT * FROM user WHERE idUser = ?"; // Ensure table name is 'user'
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error("DeserializeUser DB Error:", err);
            return done(err, null);
        }
        if (results && results.length > 0) {
            return done(null, results[0]); // User found, attach to req.user
        } else {
            // User not found with this ID, which could mean session data is stale
            // or user was deleted.
            return done(null, false, { message: 'User not found in session.' });
        }
    });
});

module.exports = passport; // Export the configured passport instance
