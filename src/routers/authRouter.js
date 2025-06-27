const express = require("express")
const router = express.Router()
const authController = require("../controllers/authController.controllers")
const { identifier } = require("../middlewares/identification")


router.post("/register",authController.signUp)
router.post("/login",authController.signIn)
router.post("/logout",identifier,authController.signOut)
router.patch("/send-verification-code",authController.sendVerificationCode)
router.patch("/verify-verification-code",authController.verifyCode)
router.patch("/change-password",identifier,authController.changePassword)

module.exports = router
