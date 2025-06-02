const authentication = require("./src/authentication/authentication.routes");
const jwtAuthentication = require("./src/authentication/jwt.middleware");
const passport = require('./src/authentication/passport.config.js'); // Import configured Passport
const express = require("express");
const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 3005;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: "*" }))
const cookie = require("cookie-parser");
app.use(cookie());

// Initialize Passport
app.use(passport.initialize());
// Note: app.use(passport.session()); is omitted intentionally for a stateless JWT approach.
// OAuth routes will use { session: false }.

// Protected API routes
const protectedApiRouter = express.Router();
protectedApiRouter.use(jwtAuthentication); // Apply JWT middleware to all routes in protectedApiRouter

// Example protected route
protectedApiRouter.get("/me", (req, res) => {
  // req.user should be populated by jwtAuthentication middleware
  if (req.user) {
    res.json({ message: "This is a protected route. User data:", user: req.user });
  } else {
    // This case should ideally not be reached if middleware is working correctly
    // and an unauthenticated user tries to access this route.
    // The jwtAuthentication middleware should send a 401/403 before this point.
    res.status(401).json({ message: "User not authenticated (should be caught by middleware)." });
  }
});

app.use("/api", protectedApiRouter); // Mount the protected router

// Public authentication routes
app.use("/authentication" ,authentication);

app.get("/", (req, res) => {
  res.send({ msg: "etafakna web server working.." });
});

app.listen(PORT, function () {
  console.log("listening on port 3005!");
});