const Joi= require("joi");

exports.signupSchema = Joi.object({
    email: Joi.string()
    .min(6)
    .max(60)
    .email({
        tlds:{allow:["com", "net"]}
    }),
    password: Joi.string()
    .required()
   .pattern(
    new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&#]{8,}$")
    )
    .message("Password must be at least 8 characters long, contain one uppercase letter, one lowercase letter, one number, and one special character")
})

exports.signInSchema = Joi.object({
    email: Joi.string()
    .min(6)
    .max(60)
    .email({
        tlds:{allow:["com", "net"]}
    }),
    password: Joi.string()
    .required()
   .pattern(
    new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,}$")
    )
    .message("Password must be at least 8 characters long, contain one uppercase letter, one lowercase letter, one number, and one special character")
})

exports.acceptCodeSchema = Joi.object({
     email: Joi.string()
    .min(6)
    .max(60)
    .email({
        tlds:{allow:["com", "net"]}
    }),
    providedCode : Joi.number().required()
})

exports.changePasswordSchema  =Joi.object({
    newPassword: Joi.string()
    .required()
   .pattern(
    new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,}$")
    ),
    oldPassword: Joi.string()
    .required()
   .pattern(
    new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,}$")
    )
})