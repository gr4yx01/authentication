import { Injectable } from "@nestjs/common";
import * as nodemailer from 'nodemailer'

@Injectable()
export class MailService {
    private transporter: nodemailer.Transporter

    constructor() {
        this.transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            auth: {
                user: 'estell.rath@ethereal.email',
                pass: 'ntxAS58R3eVwKhdg3m'
            }
        });
    }

    async sendPasswordResetTokenMail(to: string, token: string) {
        const resetLink = `https://yourwebsite.com/reset-password?token=${token}`
        const mailOptions = {
            from: 'Graey Foundation',
            to: to,
            subject: 'Password Reset Request',
            html: `<p>You requested a password reset. Click the link below to reset your password.</p><p><a href="${resetLink}">Reset Password</a></p>.`
        }

        this.transporter.sendMail(mailOptions, (error, info) => {
            if(error) {
                console.log(error)
            } else {
                console.log(info)
            }
        })
    }
}