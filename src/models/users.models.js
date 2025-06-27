const mongoose = require("mongoose")

const userSchema = mongoose.Schema({
    email : {
    type:String,
    required :[true,"email is required"],
    unique : [true,"Email must be unique"],
    minLength:[5, "Email must be atleast 5 characters"],
    lowercase: true,
    trim:true
    },
    password:{
        type : String,
        required : [true,"password must be provided"],
        trim:true,
        select:false,
    },
    verified:{
        type:Boolean,
        default:false,
    },
    verificationCode:{
        type: String,
        select:false
    },
     verificationCodeValidation: { 
        type: Date, 
        select: false 
    },
    forgotPasswordCode:{
        type: String,
        select:false
    },
    forgotPasswordCode:{
        type: Number,
        select:false
    },
    forgotPasswordCodeValidation:{
        type: Number,
        select:false
    },
},
    {timestamps:true}
)

module.exports = mongoose.model("User",userSchema)
