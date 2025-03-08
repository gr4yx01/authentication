import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
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

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        @InjectModel(RefreshToken.name) private refreshTokenModel: Model<RefreshToken>,
        private config: ConfigService,
        private jwtService: JwtService
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

        const { userId } = tokenExist

        await this.refreshTokenModel.deleteOne({ token })
        
        return this.generateToken(userId)
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

        await this.refreshTokenModel.create({
            token,
            userId,
            expiryDate
        })
    }
}
