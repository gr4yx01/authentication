import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/user.schema';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RefreshToken, RefreshTokenSchema } from './schemas/refresh-token.schema';

@Module({
  imports: [MongooseModule.forFeature([
    { name: User.name, schema: UserSchema },
    { name: RefreshToken.name, schema: RefreshTokenSchema },
  ]),
  JwtModule.registerAsync({
    useFactory: (config: ConfigService) => ({
      secret: config.get('jwt.secret'),
      signOptions: { expiresIn: config.get('jwt.expiresIn') }
    }),
    inject: [ConfigService]
  })
],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
