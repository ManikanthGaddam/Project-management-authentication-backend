import { body } from "express-validator";

const userRegisterValidator = () => {
    return [
        body("email").trim().notEmpty().withMessage("Email field is required").isEmail().withMessage("Email field is incorrect").toLowerCase(),
        body("UserName").trim().notEmpty().withMessage("username field is required").isLength({min:3}).withMessage("username should be atleast 3 characters"),
        body("password").trim().notEmpty().withMessage("password is required"),
    ];
}

const userloginValidator = () => {
    return [
        body("email").trim().notEmpty().withMessage("Email field is required").isEmail().withMessage("Email field is incorrect").toLowerCase(),
        body("password").trim().notEmpty().withMessage("password is required"),
    ]
}

const userChangePasswordValidator = () => {
    return [
        body("oldPassword").notEmpty().withMessage("old password is required"),
        body("newPassword").notEmpty().withMessage("new password is required"),
    ]
}

const userForgotPasswordValidator = () => {
    return [
        body("email").notEmpty().withMessage("email is required").isEmail().withMessage("enter valid email")
    ]
}

const userResetPasswordValidator = () => {
    return [
        body("newPassword").notEmpty().withMessage("new password is required")
    ]
}
export { userRegisterValidator, userloginValidator, userChangePasswordValidator, userForgotPasswordValidator, userResetPasswordValidator }