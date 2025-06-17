const express = require("express")
const dotenv = require("dotenv")
dotenv.config()
const cors = require("cors")
const cookieParser = require("cookie-parser")
const helmet = require("helmet")
const mongoose = require("mongoose")
const authRouter =require("./src/routers/authRouter")
const PORT = process.env.PORT || 3500

const app = express();
app.use(cors()) 
app.use(helmet())
app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({extended:true}))

const connectDb = async()=>{
    try{
        await mongoose.connect(process.env.MONGO_URL)

        console.log("database connected");
    }
    catch(err){

        console.error(err);

    }
}
connectDb();

app.use("/api/auth",authRouter)

app.get('/',(req,res)=>{
    res.json({message:"hello from server"})
})
app.listen(PORT,()=>{
    console.log("listening");
    
})

