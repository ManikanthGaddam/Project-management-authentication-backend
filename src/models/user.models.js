import mongoose,{ Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const UserSchema = new Schema(
    {
        Avatar: {
            type: {
                url: String,
                localPath: String
            },
            default: {
                url: `https://placehold.co/200x200`,
                localPath: ""
            }
        },
        UserName: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            index: true,
            lowerCase: true
        },
        FullName: {
            type: String,
            lowerCase: true,
            required: false,
            trim: true
        },
        email: {
            type: String,
            required: true,
            lowerCase: true,
            unique: true,
            trim: true
        },
        password: {
            type: String,
            required: [true, "Password is required"]
        },
        isEmailVerified: {
            type: Boolean,
            default: false
        },
        RefreshToken: {
            type: String,
        },
        forgotPasswordToken: {
            type:String
        },
        PasswordTokenExpiry: {
            type: Date
        },
        EmailVerificationToken: {
            type: String
        },
        EmailVerificationTokenExpiry: {
            type: Date
        }
    }, {
        timestamps: true,
    }
)

UserSchema.pre("save", async function(next){
    if(! this.isModified("password")) return next;

    this.password = await bcrypt.hash(this.password, 10);
    next;
});

UserSchema.methods.isPasswordCorrect = async function(password) {
    return await bcrypt.compare(password, this.password);
};

UserSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            name: this.UserName,
            email: this.email
        },
        process.env.ACCESS_TOKEN,
        {expiresIn: process.env.ACCESS_TOKEN_EXPIRY}
    )
}

UserSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id
        },
        process.env.REFRESH_TOKEN,
        {expiresIn: process.env.REFRESH_TOKEN_EXPIRY}
    )
}

UserSchema.methods.generateTemporaryToken = function(){
    const unhashedToken = crypto.randomBytes(20).toString("hex");

    const hashedToken = crypto.createHash("sha256").update(unhashedToken).digest("hex")

    const tokenExpiry = Date.now() + (20*60*1000);

    return { unhashedToken, hashedToken, tokenExpiry };
}


export const User = mongoose.model("User",UserSchema)
