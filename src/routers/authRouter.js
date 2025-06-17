const express = require("express")
const router = express.Router()
const authController = require("../controllers/authController.controllers")


router.post("/signup",authController.signUp)
router.post("/login",authController.signIn)
router.post("/logout",authController.singOut)
router.patch("/send-verification-code",authController.sendVerificationCode)

module.exports = router

