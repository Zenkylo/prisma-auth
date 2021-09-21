import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaService } from './prisma.service';
import { AuthModule } from './auth/auth.module';
import { WebAuthModule } from './web/auth/webAuth.module';
import { AuthMiddleware } from './middlewares/auth.middleware';
import { AuthService } from './auth/auth.service';
import { TokenService } from './token/token.service';
import { EmailService } from './email/email.service';

@Module({
  imports: [AuthModule, WebAuthModule],
  controllers: [AppController],
  providers: [
    AppService,
    PrismaService,
    AuthService,
    TokenService,
    EmailService,
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AuthMiddleware)
      .exclude(
        { path: 'auth/login', method: RequestMethod.POST },
        { path: 'auth/refresh', method: RequestMethod.GET },
        { path: 'auth/verify', method: RequestMethod.GET },
        { path: 'auth/register', method: RequestMethod.POST },
        { path: 'auth/password-reset', method: RequestMethod.POST },

        { path: 'web/auth/login', method: RequestMethod.GET },
        { path: 'web/auth/login', method: RequestMethod.POST },
        { path: 'web/auth/register', method: RequestMethod.GET },
        { path: 'web/auth/register', method: RequestMethod.POST },
        { path: 'web/auth/verify', method: RequestMethod.GET },
        { path: 'web/auth/password-reset', method: RequestMethod.GET },
        { path: 'web/auth/password-reset/capture', method: RequestMethod.GET },
        { path: 'web/auth/password-reset', method: RequestMethod.POST },
        { path: 'web/auth/password-reset-email', method: RequestMethod.GET },
        { path: 'web/auth/password-reset-password', method: RequestMethod.GET },
        { path: 'web/auth/password-reset/capture', method: RequestMethod.POST },
        { path: 'web/auth/password-reset-sent', method: RequestMethod.GET },
      )
      .forRoutes('/');
  }
}
