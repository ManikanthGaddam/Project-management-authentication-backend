import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";

export const validate = (req,res,next) => {
    const errors = validationResult(req);

    if(errors.isEmpty()){
        return next();
    }

    const existingErrors = [];
    errors.array().map((err) => existingErrors.push(
        { [err.path]: err.msg }
    ));

    throw new ApiError(409, "Something went wrong while validating data", existingErrors);
}