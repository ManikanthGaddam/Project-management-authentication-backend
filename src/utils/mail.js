import Mailgen from "mailgen";
import nodemailer from "nodemailer";


const sendMail = async(options) => {
    const mailgenerator = new Mailgen({
        theme: "default",
        product: {
            name: "Project Management APP",
            link: "https://projectmanagement.com"
        }
    })

    const emailHtml = mailgenerator.generate(options.mailgenContent)
    const emailtext = mailgenerator.generatePlaintext(options.mailgenContent)
    console.log(process.env.MAILTRAP_HOST);
    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_HOST,
        port: process.env.MAILTRAP_PORT,
        secure: false,
        auth : {
            user: process.env.MAILTRAP_USERNAME,
            pass: process.env.MAILTRAP_PASSWORD
        }
    });

    const mail = {
        from: "mail@testexample.com",
        to: options.email,
        subject: options.subject,
        text: emailtext,
        html: emailHtml
    }

    try {
        await transporter.sendMail(mail)
    } catch (error) {
        console.error('Email service failed silently, Please check your credentials');
        console.error('error: ',error)
    }
}

const emailVerificationMailgenContent = (username, verificationUrl) => {
        return {
            body: {
                name: username,
                intro: "Welcome to our App. We're excited to have you on board",
                action: {
                    instructions: "To verify your email, please click on the button below",
                    button: {
                        color: "#22BC66",
                        text: "Verify email",
                        link: verificationUrl
                    }
                },
                outro: "Need help or have any questions? reply to this mail"
            }

        }
}


const forgotPasswordMailgenContent = (username, passwordReset) => {
    return {
        body: {
            name: username,
            intro: "we have received a request to reset your password",
            action: {
                instructions: "To reset your password, please click on the button below",
                button: {
                    color: "#22BC66",
                    text: "Reset password",
                    link: passwordReset
                }
            },
            outro: "Need help or have any questions? reply to this mail"
        }

    }
}

export {emailVerificationMailgenContent, forgotPasswordMailgenContent, sendMail }