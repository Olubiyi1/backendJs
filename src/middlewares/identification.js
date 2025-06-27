const jwt = require("jsonwebtoken")

exports.identifier =  (req,res,next)=>{
    let token ;
    if(req.header.client === "not-browser"){
        token = req.header.authorization
    }
    else{
        token = req.cookies["Authorization"]
    }

    if(!token){
        return res.status(403).json({success: false, message:"Unauthorized"})
    }
    try{
        const userToken = token.split(" ")[1]
        const jwtVerified = jwt.verify(userToken,process.env.SECRET);
        if(jwtVerified){
            req.user = jwtVerified       
         }else{
            throw new Error("error in token")
         }
    }catch(error){

    }
}