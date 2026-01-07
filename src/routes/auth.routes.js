import { Router } from "express";
import { loginUser, registerUser, logoutUser, currentUser, refreshAccessToken, verifyEmail, forgotPasswordRequest, resetPassword, changePassword } from "../controllers/auth.controllers.js";
import {validate} from "../middlewares/validator.middleware.js";
import { userRegisterValidator, userloginValidator, userForgotPasswordValidator, userResetPasswordValidator, userChangePasswordValidator } from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

// unsecure
router.route('/register-user').post(userRegisterValidator(),validate,registerUser);
router.route('/login').post(userloginValidator(),validate,loginUser);
router.route('/refresh-token').post(refreshAccessToken);
router.route('/verify-email/:verificationToken').get(verifyEmail);
router.route('/forgot-password').post(userForgotPasswordValidator(), validate ,forgotPasswordRequest);
router.route('/reset-password/:resetToken').post(userResetPasswordValidator(), validate ,resetPassword);


// secure
router.route('/logout').post(verifyJWT,logoutUser);  
router.route('/current-user').get(verifyJWT, currentUser); 
router.route('/change-password').post(verifyJWT,userChangePasswordValidator(), validate , changePassword); 
router.route('/resend-email-verification').post(verifyJWT, changePassword); 



export default router;