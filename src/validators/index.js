import { body } from "express-validator";

const userRegisterValidator = () => {
    return [
        body("email").trim().notEmpty().withMessage("Email field is required").isEmail().withMessage("Email field is incorrect").toLowerCase(),
        body("UserName").trim().toLowerCase().withMessage("username must be in lowercase").notEmpty().withMessage("username field is required").isLength({min:3}).withMessage("username should be atleast 3 characters"),
        body("password").trim().notEmpty().withMessage("password is required"),
        body("FullName").optional().trim().toLowerCase().notEmpty()
    ];
}

export { userRegisterValidator }