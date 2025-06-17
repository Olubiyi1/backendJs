const { doHash,comparePassword } = require("../middlewares/hashing")
const transport = require("../middlewares/sendMail")
const { signupSchema, signInSchema} = require("../middlewares/userValidator.middleware")
const User = require("../models/users.models")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")


exports.signUp = async(req,res)=>{
    const {email,password} =req.body

    try{
        // can use value if i am validating everything instead of writing it like this .validate({email.....})..just write (req.body)
        const {error,value} = signupSchema.validate({email,password})

        if(error){
            return res.status(401).json({success:false,message:error.details})
        }

        const existingUser = await User.findOne({email})

        if(existingUser){
            return res.status(401).json({success:false,message:"user already exists"})
        }

        const hashedPassword = await doHash(password,12)

        // i can jst write value here inplace of listing my schema contents here if i validated all inputs (new user (value))

        const newUser = new User({
            email,
            password: hashedPassword
        })

        const result = await newUser.save()
        result.password = undefined;

        console.log(value);
        
        res.status(201).json({
            success:true, message:"user created succesfully",result
        })
    }
    catch(error){
        console.error("error encountered")
        res.status(500).json({success:false, message:"Internal server error"})
    }
}

// user singin
exports.signIn= async(req,res)=>{
    const {email,password} = req.body

    try{
        const {error,value} = signInSchema.validate({email,password})

         if(error){
            return res.status(401).json({success:false,message:error.details})
        }
        const existingUser = await User.findOne({email}).select("+ password")
       
        if(!existingUser){
            return res
            .status(401).json({success:false,message:"user does not exists"})
        }
        const result = await comparePassword(password,existingUser.password)

        if(!result){
            return res
            .status(401)
            .json({success:false,message:"invalid credentials"})
            
        }
        const token = jwt.sign({
            userId : existingUser._id,
            email: existingUser.email,
            verified: existingUser.verified
        },
        process.env.SECRET,{
            expiresIn:"8h",
        })
        res.cookie("Authorization", "Bearer" + token,{expires: new Date((Date.now()) + 8
        * 3600000),
        httpOnly:process.env.NODE_ENV === "production", 
        secure:process.env.NODE_ENV === "production"})
        
        .json({
            success: true,
            token,
            message:"logged in successful"
        })
        
    }
    catch(error){
        console.error(error);
    }
}

// user signout

exports.singOut = async(req,res)=>{
    res
    .clearCookie("Authorization")
    .status(200)
    .json({
        success: true,
        message:"signed out successfully"
    })
}

// send verification mail
exports.sendVerificationCode = async(req,res)=>{
    const {email} = req.body

    try{

            const existingUser = await User.findOne({email})
            if(!existingUser){
            return res
            .status(404).json({success:false,message:"user does not exists"})

            // check of user is already verified
        }
        if(existingUser.verified){
            return res
            .status(400)
            .json({success: false, message:"You are already verified"})
        }
        // Generate secure 6-digit code using crypto
        const codeValue = crypto.randomInt(100000, 999999).toString();

        // Store the code in database with expiry 10mins
        const codeExpiry = new Date(Date.now() + 10 * 60 * 1000); 
        await User.updateOne(
            { email },
            { 
                verificationCode: codeValue,
                codeExpiry: codeExpiry 
            }
        );

        // send email
        let info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL,
            to: existingUser.email,
            subject: "Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Email Verification</h2>
                    <p>Your verification code is:</p>
                    <div style="background: #f0f0f0; padding: 20px; text-align: center; margin: 20px 0;">
                        <h1 style="color: #333; font-size: 32px; letter-spacing: 3px;">${codeValue}</h1>
                    </div>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </div>
            `
        });

        if (info.accepted.includes(existingUser.email)) {
            // Email was successfully accepted for delivery
            return res.status(200).json({
                success: true,
                message: "Verification code sent successfully"
            });
        } else if (info.rejected.includes(existingUser.email)) {
            // Email was explicitly rejected
            return res.status(400).json({
                success: false,
                message: "Email address rejected by server"
            });
        } else {
            // Something else went wrong
            return res.status(500).json({
                success: false,
                message: "Failed to send verification code"
            });
        }
    }catch(error){
    console.log(error);
     return res.status(500).json({
    success: false,
    message: "Something went wrong while sending verification code"
  });
    }
}
