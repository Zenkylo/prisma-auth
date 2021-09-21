import { AuthService } from './auth.service';
import { LoginAuthDto } from './dto/login-auth.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResetPasswordAuthDto } from './dto/reset-password-auth.dto';
import { Request } from 'express';
export declare class AuthController {
    private readonly authService;
    constructor(authService: AuthService);
    create(loginAuthDto: LoginAuthDto, response: Response): Promise<unknown>;
    register(registerAuthDto: RegisterAuthDto, response: Response): Promise<unknown>;
    refresh(request: Request, response: Response): Promise<unknown>;
    verifyUser(token: string): Promise<unknown>;
    getMe(request: Request): Promise<unknown>;
    createPasswordReset(request: Request): Promise<unknown>;
    getPasswordReset(token: string): Promise<unknown>;
    updatePassword(token: string, resetPassAuthDto: ResetPasswordAuthDto): Promise<unknown>;
    renderAuthRegister(): {
        message: string;
    };
}
