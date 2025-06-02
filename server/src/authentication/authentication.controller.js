const {
  addUserService,
  getUserByEmailAndPasswordService,
} = require("../user/user.service");
const {
  generateAccessToken,
  generateRefreshToken,
  storeRefreshToken,
  validateRefreshToken,
  deleteRefreshToken
} = require("./authentication.service");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const registerController = async (req, res) => {
  try {
    const { email, password } = req.body;

    bcrypt.genSalt(13, function (err, salt) {
      bcrypt.hash(password, salt, async function (err, password) {
        try {
          const result = await addUserService({ email, password });
          if (result === null) {
            res
              .status(200)
              .json({ message: "No user were registred.", ok: false });
          } else {
            res
              .status(200)
              .json({ message: "user registred successfully.", ok: true });
          }
        } catch (error) {
          return res.json({ error: error?.message ? error.message : error });
        }
      });
    });
  } catch (error) {
    return res.json({ error: error?.message ? error.message : error });
  }
};
const loginController = async (req, res) => {
  
  try {
    const { email, password } = req.body;
    const hashpassword = await getUserByEmailAndPasswordService(email);
    if (!hashpassword) {
      res.status(404).json({ message: "User not found.", ok: false });
    } else {
      bcrypt.compare(password, hashpassword[0].password, async function (err, result) { // Made async
        if (err) {
          console.error("Error comparing password:", err);
          return res.status(500).json({ message: "Internal server error during login" });
        }
        if (result) {
          const userPayload = {
            id: hashpassword[0].idUser,
            email: hashpassword[0].email,
          };
          const token = generateAccessToken(userPayload);
          const refreshTokenString = generateRefreshToken(userPayload);

          // Calculate expiry for the refresh token (e.g., 7 days from now)
          const refreshTokenExpiryMs = parseInt(process.env.REFRESH_TOKEN_EXPIRY_MS || '604800000'); // 7 days in ms
          const expiresAt = new Date(Date.now() + refreshTokenExpiryMs);

          try {
            await storeRefreshToken(userPayload.id, refreshTokenString, expiresAt);
          } catch (dbError) {
            console.error("Failed to store refresh token:", dbError);
            // Decide if login should fail or proceed with a warning
            return res.status(500).json({ message: "Login failed: Could not save session." });
          }

          res
            .status(200)
            .cookie("refreshtoken", refreshTokenString, {
              httpOnly: true,
              secure: true,
            })
            .cookie("jwt", token, {
              httpOnly: true,
              secure: true,
            })
            .json({
              message: "User logged successfully",
              ok: true,
              token,
              refreshtoken: refreshTokenString // send the string
            });
            
        } else {
          res
            .status(200)
            .json({ message: "not credentials matching", ok: false });
        }
      });
    }
  } catch (error) {
    console.error("Login controller error:", error);
    res.status(500).json({ error: error?.message ? error.message : error });
  }
};

module.exports = {
  registerController,
  loginController,
  refreshTokenController,
  logoutController
};

const logoutController = async (req, res) => {
  const refreshToken = req.cookies.refreshtoken;
  // req.user should be populated by JWT middleware if an access token was provided
  const userId = req.user ? req.user.user.id : null;

  if (refreshToken && userId) {
    try {
      await deleteRefreshToken(userId, refreshToken);
    } catch (error) {
      // Log the error but don't let it prevent logout from client-side perspective
      console.error("Error deleting refresh token from DB during logout:", error);
    }
  } else if (userId && !refreshToken) {
     // If no refresh token cookie, but user is authenticated (e.g. access token still valid)
     // we might want to delete all tokens for that user as a safety measure,
     // or rely on access token expiry. For now, we'll only act if refresh token is present.
     console.log("Logout attempt by authenticated user without a refresh token cookie. No server-side token to delete based on cookie.");
  }


  // Always clear cookies
  res.clearCookie("refreshtoken", { httpOnly: true, secure: true, sameSite: 'Strict' });
  res.clearCookie("jwt", { httpOnly: true, secure: true, sameSite: 'Strict' });

  return res.status(200).json({ message: "Logout successful", ok: true });
};


const refreshTokenController = async (req, res) => {
  const refreshToken = req.cookies.refreshtoken;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Unauthorized: No refresh token provided' });
  }

  try {
    // Verify the refresh token structure and expiry (signature was already checked by cookie parser or earlier middleware if any)
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const userId = decoded.user.id;

    // Validate token against database
    const isValidInDB = await validateRefreshToken(userId, refreshToken);
    if (!isValidInDB) {
      // Clear potentially compromised or old token
      res.clearCookie("refreshtoken", { httpOnly: true, secure: true });
      res.clearCookie("jwt", { httpOnly: true, secure: true });
      return res.status(403).json({ message: 'Forbidden: Invalid or revoked refresh token' });
    }

    // Token is valid and in DB, proceed with rotation:
    // 1. Delete the old refresh token
    await deleteRefreshToken(userId, refreshToken);

    // 2. Generate new access token and new refresh token
    const userPayload = { id: userId, email: decoded.user.email };
    const newAccessToken = generateAccessToken(userPayload);
    const newRefreshTokenString = generateRefreshToken(userPayload);

    // 3. Store the new refresh token
    const refreshTokenExpiryMs = parseInt(process.env.REFRESH_TOKEN_EXPIRY_MS || '604800000'); // 7 days
    const newExpiresAt = new Date(Date.now() + refreshTokenExpiryMs);
    await storeRefreshToken(userId, newRefreshTokenString, newExpiresAt);

    // 4. Send new tokens to client
    res
      .status(200)
      .cookie("refreshtoken", newRefreshTokenString, {
        httpOnly: true,
        secure: true,
        // sameSite: 'Strict'
      })
      .cookie("jwt", newAccessToken, {
        httpOnly: true,
        secure: true,
        // sameSite: 'Strict'
      })
      .json({
        message: "Tokens refreshed successfully",
        ok: true,
        token: newAccessToken,
      });

  } catch (error) {
    // Clear cookies on any error during refresh token processing
    res.clearCookie("refreshtoken", { httpOnly: true, secure: true });
    res.clearCookie("jwt", { httpOnly: true, secure: true });

    if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
      return res.status(403).json({ message: 'Forbidden: Invalid or expired refresh token signature' });
    }
    console.error('Refresh token controller error:', error);
    return res.status(500).json({ message: 'Internal server error during token refresh' });
  }
};
