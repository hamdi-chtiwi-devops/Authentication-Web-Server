const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
  let token = null;

  // Attempt to extract token from cookie
  if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
  } else {
    // Attempt to extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7, authHeader.length);
    }
  }

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach decoded user info to request object
    next(); // Pass control to the next middleware or route handler
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Unauthorized: Token expired' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ message: 'Forbidden: Invalid token' });
    }
    // Handle other unexpected errors
    console.error('JWT verification error:', error);
    return res.status(500).json({ message: 'Internal server error during token verification' });
  }
};

module.exports = verifyToken;
