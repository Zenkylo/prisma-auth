import { HttpException, Injectable, NestMiddleware, } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private readonly authService: AuthService) {}
  async use(req: Request, res: Response, next: NextFunction) {
    try {
      await this.authService.validateRequest(req);
    } catch (err) {
      throw new HttpException('unauthorized resource', 401);
    }
    next();
  }
}
