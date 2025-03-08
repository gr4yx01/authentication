import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { Mongoose } from 'mongoose';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { dbConfig } from './config/db.config';
import { authConfig } from './config/auth.config';
import { JwtService } from '@nestjs/jwt';

@Module({
  imports: [
    AuthModule,
    MongooseModule.forRootAsync({
    useFactory: async (config: ConfigService) => ({
      uri: config.get('db.uri')
    }),
    inject: [ConfigService]
  }),
  ConfigModule.forRoot({
    isGlobal: true,
    load: [dbConfig, authConfig],
    cache: true
  })
],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
