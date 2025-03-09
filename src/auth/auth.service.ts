import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import { SignupDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt'
import { LoginDto } from './dtos/login.dto';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { ResetToken } from './schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        @InjectModel(RefreshToken.name) private refreshTokenModel: Model<RefreshToken>,
        @InjectModel(ResetToken.name) private resetTokenModel: Model<RefreshToken>,
        private config: ConfigService,
        private jwtService: JwtService,
        private mailService: MailService
    ) {}

    async register(body: SignupDto) {

        const { email, password, name } = body

        const emailExist = await this.userModel.findOne({ email })

        if(emailExist) {
            throw new BadRequestException("Email already exists");
        }

        const salt = Number(this.config.get('bcrypt.saltOrRounds'))

        const hashedPassword = await bcrypt.hash(password, salt);
        
        return await this.userModel.create({
            email,
            password: hashedPassword,
            name
        })
    }

    async login(body: LoginDto) {
        const { email, password } = body

        const userExist = await this.userModel.findOne({ email })

        if(!userExist) {
            throw new NotFoundException("Account not found");
        }

        const passwordMatch = await bcrypt.compare(password, userExist?.password)

        if(!passwordMatch) {
            throw new BadRequestException("Invalid email or password");
        }

        return this.generateToken(userExist._id)
    }

    async refreshToken(token: string) {
        const tokenExist = await this.refreshTokenModel.findOne({ 
            token, 
            expiryDate: { $gte: new Date()}
        })

        if(!tokenExist) {
            throw new NotFoundException("Invalid token")
        }

        return this.generateToken(tokenExist.userId)
    }

    async changePassword(oldPassword: string, newPassword: string, userId: string) {
        const userExist = await this.userModel.findById(userId)

        if(!userExist) {
            throw new NotFoundException("Account not found")
        }

        const oldPasswordMatch = await bcrypt.compare(oldPassword, userExist.password)

        if(!oldPasswordMatch) {
            throw new BadRequestException("Old password is incorrect")
        }

        const password = await bcrypt.hash(newPassword, Number(this.config.get('bcrypt.saltOrRounds')))

        userExist.password = password

        userExist.save()

        return userExist
    }

    async forgetPassword(email: string) {
        const userExist = await this.userModel.findOne({ email })

        if(userExist) {
            const token = nanoid(64)

            const expiryDate = new Date()

            expiryDate.setHours(expiryDate.getHours() + 1)

            await this.resetTokenModel.updateOne({
                userId: userExist._id
            }, { $set: { token, userId: userExist._id, expiryDate } }, { upsert: true}
        )

        this.mailService.sendPasswordResetTokenMail(email, token)
        }

        return {
            "message": "Password reset link has been sent to your email"
        }
    }

    async resetPassword(token: string, password: string) {
        const resetTokenExist = await this.resetTokenModel.findOneAndDelete({ token }, { expiryDate: { $gte: new Date() } })

        if(!resetTokenExist) {
            throw new UnauthorizedException('Invalid Refresh Token')
        }

        const user = await this.userModel.findById(resetTokenExist.userId)

        if(!user) {
            throw new NotFoundException('User not found')
        }

        user.password = await bcrypt.hash(password, Number(this.config.get('bcrypt.saltOrRounds')))

        await user.save()
    }

    async generateToken(userId) {
        const accessToken = this.jwtService.sign({ userId })
        const refreshToken = uuidv4()

        await this.storeRefreshToken(refreshToken, userId)
        
        return {
            accessToken,
            refreshToken
        }
    }

    async storeRefreshToken(token: string, userId) {
        const expiryDate = new Date()

        expiryDate.setDate(expiryDate.getDate() + 3)

        await this.refreshTokenModel.updateOne({
            token,
            userId
        }, { $set: { expiryDate, token } }, { upsert: true })

    }
}
