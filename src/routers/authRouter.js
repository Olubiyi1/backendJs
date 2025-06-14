const express = require("express")
const router = express.Router()
const authController = require("../controllers/authController.controllers")


router.post("/signup",authController.signUp)
router.post("/login",authController.signIn)
router.post("/signout",authController.singOut)

module.exports = router

