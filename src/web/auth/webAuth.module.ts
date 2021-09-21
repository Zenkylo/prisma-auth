import { Module } from '@nestjs/common';
import { AuthService } from 'src/auth/auth.service';
import { WebAuthController } from './webAuth.controller';
import { PrismaService } from '../../prisma.service';
import { TokenService } from 'src/token/token.service';
import { EmailService } from 'src/email/email.service';

@Module({
  controllers: [WebAuthController],
  providers: [AuthService, PrismaService, TokenService, EmailService],
})
export class WebAuthModule {}
