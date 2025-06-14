const { doHash,comparePassword } = require("../middlewares/hashing")
const { signupSchema, signInSchema} = require("../middlewares/userValidator.middleware")
const User = require("../models/users.models")
const jwt = require("jsonwebtoken")

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

exports.sendVerificationCode = async(req,res)=>{
    const {email} = req.body

    try{

    }
    catch(error){
        console.log(error);
        
    }
}