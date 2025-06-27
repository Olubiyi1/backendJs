const { doHash, comparePassword } = require("../middlewares/hashing");
const transport = require("../middlewares/sendMail");
const { signupSchema, signInSchema, acceptCodeSchema } = require("../middlewares/userValidator.middleware");
const User = require("../models/users.models");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

exports.signUp = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Validate input
        const { error, value } = signupSchema.validate({ email, password });

        if (error) {
            return res.status(400).json({
                success: false,
                message: error.details[0].message
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "User already exists"
            });
        }

        // Hash password
        const hashedPassword = await doHash(password, 12);

        // Create new user
        const newUser = new User({
            email,
            password: hashedPassword
        });

        const result = await newUser.save();
        
        // Remove password from response
        const userResponse = result.toObject();
        delete userResponse.password;

        res.status(201).json({
            success: true,
            message: "User created successfully",
            data: userResponse
        });

    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

exports.signIn = async (req, res) => {
   
    console.log("received body:" , req.body);
    const { email, password } = req.body;
     
    try {
        // Validate input
        const { error, value } = signInSchema.validate({ email, password });

        if (error) {
            return res.status(400).json({
                success: false,
                message: error.details[0].message
            });
        }

        // Find user with password field
        const existingUser = await User.findOne({email}).select("+password");

        if (!existingUser) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        // Compare password
        const isPasswordValid = await comparePassword(password, existingUser.password);

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                userId: existingUser._id,
                email: existingUser.email,
                verified: existingUser.verified
            },
            process.env.SECRET,
            {
                expiresIn: "8h"
            }
        );

        // Set secure cookie
        const cookieOptions = {
            expires: new Date(Date.now() + 8 * 60 * 60 * 1000), // 8 hours
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax"
        };

        res.cookie("Authorization", `Bearer ${token}`, cookieOptions)
           .status(200)
           .json({
               success: true,
               message: "Logged in successfully",
               token,
               user: {
                   id: existingUser._id,
                   email: existingUser.email,
                   verified: existingUser.verified
               }
           });

    } catch (error) {
        console.error("Signin error:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

exports.signOut = async (req, res) => {
    try {
        res.clearCookie("Authorization")
           .status(200)
           .json({
               success: true,
               message: "Signed out successfully"
           });
    } catch (error) {
        console.error("Signout error:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

exports.sendVerificationCode = async (req, res) => {
    const { email } = req.body;

    try {
        // Validate email format
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                success: false,
                message: "Please provide a valid email address"
            });
        }

        // Find user
        const existingUser = await User.findOne({ email });
        
        if (!existingUser) {
            return res.status(404).json({
                success: false,
                message: "User does not exist"
            });
        }

        // Check if user is already verified
        if (existingUser.verified) {
            return res.status(400).json({
                success: false,
                message: "You are already verified"
            });
        }

        // Generate secure 6-digit code
        const codeValue = crypto.randomInt(100000, 999999).toString();
        const hashedCode = crypto.createHash("sha256").update(codeValue).digest("hex");

        // Set expiration time (10 minutes from now)
        const verificationCodeValidation = new Date(Date.now() + 10 * 60 * 1000);

        // Update user with verification code
        await User.updateOne(
            { email },
            {
                verificationCode: hashedCode,
                verificationCodeValidation: verificationCodeValidation
            }
        );

        // Send verification email
        const info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL,
            to: existingUser.email,
            subject: "Email Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #333; text-align: center;">Email Verification</h2>
                    <p>Hello,</p>
                    <p>You have requested to verify your email address. Please use the verification code below:</p>
                    <div style="background: #f8f9fa; border: 2px solid #e9ecef; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
                        <h1 style="color: #007bff; font-size: 32px; letter-spacing: 3px; margin: 0;">${codeValue}</h1>
                    </div>
                    <p><strong>Important:</strong> This code will expire in 10 minutes.</p>
                    <p>If you didn't request this verification, please ignore this email.</p>
                    <hr style="margin: 20px 0; border: none; border-top: 1px solid #e9ecef;">
                    <p style="font-size: 12px; color: #6c757d;">This is an automated message, please do not reply.</p>
                </div>
            `
        });

        // Check email delivery status
        if (info.accepted && info.accepted.includes(existingUser.email)) {
            return res.status(200).json({
                success: true,
                message: "Verification code sent successfully"
            });
        } else if (info.rejected && info.rejected.includes(existingUser.email)) {
            return res.status(400).json({
                success: false,
                message: "Email address was rejected by the server"
            });
        } else {
            return res.status(500).json({
                success: false,
                message: "Failed to send verification code"
            });
        }

    } catch (error) {
        console.error("Send verification code error:", error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong while sending verification code"
        });
    }
};

exports.verifyCode = async (req, res) => {
    const { email, providedCode } = req.body;

    try {
        // Validate input
        const { error, value } = acceptCodeSchema.validate({ email, providedCode });

        if (error) {
            return res.status(400).json({
                success: false,
                message: error.details[0].message
            });
        }

        // Find user with verification fields
        const existingUser = await User.findOne({ email }).select("+verificationCode +verificationCodeValidation");

        if (!existingUser) {
            return res.status(404).json({
                success: false,
                message: "User does not exist"
            });
        }

        // Check if already verified
        if (existingUser.verified) {
            return res.status(400).json({
                success: false,
                message: "You are already verified"
            });
        }

        // Check if verification code exists
        if (!existingUser.verificationCode || !existingUser.verificationCodeValidation) {
            return res.status(400).json({
                success: false,
                message: "No verification code found. Please request a new one."
            });
        }

        // Check if code has expired
        if (Date.now() > existingUser.verificationCodeValidation.getTime()) {
            return res.status(400).json({
                success: false,
                message: "Verification code has expired. Please request a new one."
            });
        }

        // Hash the provided code and compare
        const hashedProvidedCode = crypto
            .createHash("sha256")
            .update(providedCode.toString())
            .digest("hex");

        if (hashedProvidedCode !== existingUser.verificationCode) {
            return res.status(400).json({
                success: false,
                message: "Invalid verification code"
            });
        }

        // Verification successful - update user
        existingUser.verified = true;
        existingUser.verificationCode = undefined;
        existingUser.verificationCodeValidation = undefined;

        await existingUser.save();

        console.log("verifcation successful");
        
        res.status(200).json({
            success: true,
            message: "Account verified successfully"
        });

    } catch (error) {
        console.error("Verification error:", error);
        res.status(500).json({
            success: false,
            message: "Server error. Please try again."
        });
    }
};

// This function handles changing a user's password
exports.changePassword = async (req, res) => {

    // Step 1: Get the information we need from the request

    // Who is making the request
    const { userId, verified } = req.user;  

    // The passwords they provided
    const { oldPassword, newPassword } = req.body; 

    try {
        // Step 2: Validate the password format (check if they meet requirements)
        const { error, value } = changePasswordSchema.validate({ oldPassword, newPassword });
        
        if (error) {
            return res.status(400).json({
                success: false, 
                message: error.details[0].message  // Fixed typo: "details" not "deatils"
            });
        }

        // Step 3: Check if user has verified their account (like email verification)
        if (!verified) {
            return res.status(403).json({
                success: false, 
                message: "Please verify your account before changing password"
            });
        }

        // Step 4: Find the user in the database and get their current password
        const existingUser = await User.findOne({ _id: userId }).select("+password");

        if (!existingUser) {
            return res.status(404).json({
                success: false, 
                message: "User account not found"
            });
        }

        // Step 5: Check if the old password they entered is correct
        const isOldPasswordCorrect = await doHash(oldPassword, existingUser.password);

        if (!isOldPasswordCorrect) {
            return res.status(401).json({
                success: false, 
                message: "Current password is incorrect"
            });
        }

        // Step 6: Hash the new password for security
        const hashedNewPassword = await doHash(newPassword,12);

        // Step 7: Update the user's password in the database
        await User.findByIdAndUpdate(userId, { 
            password: hashedNewPassword 
        });

        // Step 8: Send success response (don't include the actual password!)
        return res.status(200).json({
            success: true,
            message: "Password changed successfully"
        });

    } catch (error) {
        // Step 9: Handle any unexpected errors
        console.log("Error changing password:", error);
        
        return res.status(500).json({
            success: false,
            message: "Something went wrong. Please try again later."
        });
    }
};

