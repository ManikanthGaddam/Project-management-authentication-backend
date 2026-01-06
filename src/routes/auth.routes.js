import { Router } from "express";
import { loginUser, registerUser } from "../controllers/auth.controllers.js";
import {validate} from "../middlewares/auth.middleware.js";
import { userRegisterValidator } from "../validators/index.js";

const router = Router();


router.route('/register-user').post(userRegisterValidator(),validate,registerUser)
router.route('/login').post(loginUser)

export default router;