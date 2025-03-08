import { IsEmail, IsNotEmpty, IsString, Matches, MinLength } from 'class-validator'

export class LoginDto {
    @IsEmail()
    @IsNotEmpty()
    email: string

    @IsString()
    @MinLength(8)
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, {
        message: 'Password must contain at least 8 characters, one letter and one number'
    })
    password: string
}