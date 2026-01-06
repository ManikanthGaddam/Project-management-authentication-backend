import {User} from "../models/user.models.js"
import {ApiResponse} from "../utils/api-response.js"
import {ApiError} from "../utils/api-error.js"
import { asyncHandler } from "../utils/async-handler.js"
import { sendMail } from "../utils/mail.js"
import { emailVerificationMailgenContent } from "../utils/mail.js"
import cookieParser from "cookie-parser"


const generateAccessTokenAndRefreshToken = async function (userId) {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.RefreshToken = refreshToken;
        await user.save({validateBeforeSave: false});
        return {accessToken, refreshToken};
    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating tokens", []);
    }
}


const registerUser = asyncHandler (async (req,res) => {
    const {email, password, Username, role} = req.body;
    console.log(req.body);
    const userExist = await User.findOne({
        $or: [{email},{Username}]
    })

    if(userExist){
        throw new ApiError(409,"User already Exists",[]);
    }

    const user = await User.create({
        email,
        UserName: Username,
        password,
        isEmailVerified: false
    })

    const {unhashedToken, hashedToken, tokenExpiry} = user.generateTemporaryToken();

    user.EmailVerificationToken = hashedToken;
    user.EmailVerificationTokenExpiry = tokenExpiry;

    await user.save({validateBeforeSave: false});

    await sendMail({
        email: user.email,
        subject: "please Verify your Email",
        mailgenContent: emailVerificationMailgenContent(
            user.UserName,
            `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unhashedToken}`
        )
    })
    console.log(req.body);

    const createdUSer = await User.findById(user._id).select(
        "-password -RefreshToken -EmailVerificationToken -EmailVerificationTokenExpiry -FullName"
    )

    if(!createdUSer){
        throw new ApiError(500, "Something went wrong while creating user",[]);
    }

    return res.status(200).json( new ApiResponse(
        200,
        {user: createdUSer},
        "User created succesfully"
    ));

});

const loginUser = asyncHandler( async (req,res) => {
    const { email, UserName, password } = req.body;

    if( !email ){
        throw new ApiError(400,"email is required");
    }

    const user =await User.findOne( { email } );

    const isPasswordValid = user.isPasswordCorrect(password);

    if( ! isPasswordValid ){
        throw new ApiError(400,"Wrong credentials");
    }

    const {accessToken,refreshToken} = await generateAccessTokenAndRefreshToken(user._id);

    const loggedUser = await User.findById(user._id).select(
        "-password -RefreshToken -EmailVerificationToken -EmailVerificationTokenExpiry -FullName"
    )
    
    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
            .cookie("accessToken",accessToken,options)
            .cookie("refreshToken",refreshToken,options)
            .json(
                new ApiResponse(
                    200,
                    {
                        user: loggedUser,
                        accessToken,
                        refreshToken
                    },
                    "User logged in succesfully",
                )
            );
});

export {loginUser , registerUser}