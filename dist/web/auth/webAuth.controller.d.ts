import { AuthService } from 'src/auth/auth.service';
import { LoginAuthDto } from 'src/auth/dto/login-auth.dto';
import { RegisterAuthDto } from 'src/auth/dto/register-auth.dto';
import { ResetPasswordAuthDto } from 'src/auth/dto/reset-password-auth.dto';
import { Request } from 'express';
export declare class WebAuthController {
    private readonly authService;
    constructor(authService: AuthService);
    renderAuthLogin(): void;
    create(loginAuthDto: LoginAuthDto, response: Response): Promise<unknown>;
    renderAuthRegister(): void;
    register(registerAuthDto: RegisterAuthDto, response: Response): Promise<unknown>;
    renderAuthPasswordResetEmail(): void;
    createPasswordReset(request: Request): Promise<unknown>;
    renderAuthPasswordResetPassword(token: string): Promise<unknown>;
    renderAuthPasswordResetPasswordSuccess(token: string, resetPassAuthDto: ResetPasswordAuthDto): Promise<unknown>;
    verifyUser(token: string): Promise<unknown>;
}
