import { Body, Controller, Post, Req, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refreshToken.dto';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { AuthGuard } from 'src/guards/auth.guard';
import { ForgetPasswordDto } from './dtos/forget-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/signup')
  async register(@Body() body: SignupDto) {
    return this.authService.register(body);
  }

  @Post('/signin')
  async login(@Body() body: LoginDto) {
    return this.authService.login(body)
  }

  @Post('/refresh')
  async refreshToken(@Body() refreshToken: RefreshTokenDto) {
    return this.authService.refreshToken(refreshToken?.token)
  }

  // change password
  @UseGuards(AuthGuard)
  @Post('/change-password')
  async changePassword(@Body() body: ChangePasswordDto, @Request() req) {
    const { oldPassword, newPassword } = body

    return this.authService.changePassword(oldPassword, newPassword, req.user) 
  }

  // forget password
  @Post('/forget-password')
  async forgetPassword(@Body() body: ForgetPasswordDto) {
    return this.authService.forgetPassword(body.email)
  }

  // reset password
}
