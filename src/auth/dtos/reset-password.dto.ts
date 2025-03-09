import { IsString, Matches, MinLength } from "class-validator";

export class ResetPasswordDto {
    @IsString()
    @MinLength(8)
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, {
        message: 'Password must contain at least 8 characters, one letter and one number'
    })
    password: string;

    @IsString()
    token: string;
}