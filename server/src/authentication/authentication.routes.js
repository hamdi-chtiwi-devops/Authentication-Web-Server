const {
    registerController,
    loginController,
    refreshTokenController,
    logoutController
  } = require("./authentication.controller");



const router = require("express").Router();

router.post("/register", registerController);
router.post("/login", loginController);
router.post("/refresh-token", refreshTokenController);
router.post("/logout", logoutController); // Added logout route



module.exports = router;
