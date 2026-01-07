import { User } from "../models/user.models.js"
import { ApiResponse } from "../utils/api-response.js"
import { ApiError } from "../utils/api-error.js"
import { asyncHandler } from "../utils/async-handler.js"
import { sendMail } from "../utils/mail.js"
import { emailVerificationMailgenContent, forgotPasswordMailgenContent } from "../utils/mail.js"
import cookieParser from "cookie-parser"
import crypto from "crypto"
import jwt from "jsonwebtoken"


const generateAccessTokenAndRefreshToken = async function (userId) {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.RefreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });
        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating tokens", []);
    }
}


const registerUser = asyncHandler(async (req, res) => {
    const { email, password, Username, role } = req.body;
    console.log(req.body);
    const userExist = await User.findOne({
        $or: [{ email }, { Username }]
    })

    if (userExist) {
        throw new ApiError(409, "User already Exists", []);
    }

    const user = await User.create({
        email,
        UserName: Username,
        password,
        isEmailVerified: false
    })

    const { unhashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    user.EmailVerificationToken = hashedToken;
    user.EmailVerificationTokenExpiry = tokenExpiry;

    await user.save({ validateBeforeSave: false });

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

    if (!createdUSer) {
        throw new ApiError(500, "Something went wrong while creating user", []);
    }

    return res.status(200).json(new ApiResponse(
        200,
        { user: createdUSer },
        "User created succesfully"
    ));

});

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
        throw new ApiError(400, "email is required");
    }

    const user = await User.findOne({ email });

    const isPasswordValid = user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(400, "Wrong credentials");
    }

    const { accessToken, refreshToken } = await generateAccessTokenAndRefreshToken(user._id);

    const loggedUser = await User.findById(user._id).select(
        "-password -RefreshToken -EmailVerificationToken -EmailVerificationTokenExpiry -FullName"
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
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

const logoutUser = asyncHandler(async (req, res) => {
    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                RefreshToken: ""
            }
        },
        {
            new: true
        }
    );

    const options = {
        httpOnly: true,
        secure: true
    };

    return res.status(200).clearCookie("accessToken", options).clearCookie("refreshToken", options)
        .json(
            new ApiResponse(
                200,
                {},
                "user logged out successfully"
            )
        )
})

const currentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, req.user, "user details fetched succesfully")
    );

})

const verifyEmail = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params;

    if (!verificationToken) {
        throw new ApiError(400, "Token is missing");
    }

    const decodedToken = crypto.createHash("sha256").update(verificationToken).digest("hex");

    const user = await User.findOne({
        EmailVerificationToken: decodedToken,
        EmailVerificationTokenExpiry: { $gt: Date.now() }
    })

    if (!user) {
        throw new ApiError(400, "Token is expired or invalid");
    }

    user.EmailVerificationToken = undefined;
    user.EmailVerificationTokenExpiry = undefined;

    user.isEmailVerified = true;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json(
        new ApiResponse(
            200,
            {
                isEmailVerified: true,
            },
            "Email is verified successfully"
        )
    );
})

const resendEmailVerification = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (!user) {
        throw new ApiError(401, "User does not exist");
    }

    if (user.isEmailVerified) {
        throw new ApiError(409, "Email is already verified");
    }

    const { unhashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    user.EmailVerificationToken = hashedToken;
    user.EmailVerificationTokenExpiry = tokenExpiry;

    await user.save({ validateBeforeSave: false });

    await sendMail({
        email: user.email,
        subject: "please Verify your Email",
        mailgenContent: emailVerificationMailgenContent(
            user.UserName,
            `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unhashedToken}`
        )
    });

    return res.status(200).json(
        new ApiResponse(
            200,
            {},
            "email verification link is sent to your EmailId"
        )
    );

})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingrefreshToken = req.cookies?.refreshToken || req.body.refreshToken;
    if (!incomingrefreshToken) {
        throw new ApiError(401, "Unauthorized access");
    }

    try {
        const decodedToken = jwt.verify(incomingrefreshToken, process.env.REFRESH_TOKEN);

        const user = await User.findById(decodedToken?._id);
        if (!user) {
            throw new ApiError(401, "Invalid token");
        }

        if (incomingrefreshToken !== user.RefreshToken) {
            throw new ApiError(404, "Refresh token expired");
        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, refreshToken } = generateAccessTokenAndRefreshToken(user._id);

        user.RefreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken },
                    "Generated access token successfully"
                )
            );

    } catch (error) {
        throw new ApiError(401, "Invalid refresh token");
    }
})

const forgotPasswordRequest = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
        throw new ApiError(401, "user does not exist");
    }
    const { unhashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();
    user.forgotPasswordToken = hashedToken;
    user.PasswordTokenExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    await sendMail({
        email: user.email,
        subject: "forgot password request",
        mailgenContent: forgotPasswordMailgenContent(
            user.UserName,
            `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unhashedToken}`
        )
    });

    return res.status(200)
        .json(
            new ApiResponse(
                200,
                {},
                "password reset email has been sent successfully"
            )
        )
})

const resetPassword = asyncHandler(async (req,res) => {
    const { resetToken } = req.params;
    const { newPassword } = req.body;
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    const user = User.findOne({
        forgotPasswordToken: hashedToken,
        PasswordTokenExpiry: {$gt: Date.now()}
    })

    if( !user) {
        throw new ApiError(401, "Token is invalid or expired")
    }

    user.forgotPasswordToken = undefined;
    user.PasswordTokenExpiry = undefined;

    user.password = newPassword;
    await user.save({validateBeforeSave: false});

    return res.status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "Password reset succesful"
                )
            )
})

const changePassword = asyncHandler(async (req,res) => {
    const {oldPassword, newPassword} = req.body;
    const user = await User.findOne({
        password: oldPassword
    });

    const isPasswordValid = await user.isPasswordCorrect(oldPassword);

    if(! isPasswordValid){ 
        throw new ApiError(401, "old Password is incorrect");
    }

    if( !user ){
        throw new ApiError(401, "User doesn't exist");
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false});

    return res.status(200).json(
        new ApiResponse(
            200,
            {},
            "password changed succesfully"
        )
    );
});

export {
    loginUser,
    registerUser, 
    logoutUser, 
    currentUser, 
    verifyEmail, 
    resendEmailVerification, 
    refreshAccessToken, 
    forgotPasswordRequest,
    resetPassword,
    changePassword
}