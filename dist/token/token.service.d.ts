import { PasswordReset, PASSWORD_RESET_STATUS, RefreshToken, User } from '.prisma/client';
import { PrismaService } from '../prisma.service';
export declare class TokenService {
    private prisma;
    constructor(prisma: PrismaService);
    private ACCESS_TOKEN_EXPIRES_MINUTES;
    private ACCESS_TOKEN_SECRET;
    private REFRESH_TOKEN_EXPIRES_MINUTES;
    private REFRESH_TOKEN_SECRET;
    private VERIFY_USER_TOKEN_SECRET;
    private PASSWORD_RESET_TOKEN_EXPIRES_MINUTES;
    private PASSWORD_RESET_TOKEN_SECRET;
    decodeAccessToken(token: string): Promise<any>;
    decodeRefreshToken(token: string): Promise<any>;
    decodeVerifyUserToken(token: string): Promise<any>;
    decodePasswordResetToken(token: string): Promise<any>;
    createAccessTokenJWT(payload: {
        user: User;
        expires: string;
    }): Promise<string>;
    createRefreshTokenJWT(payload: {
        user_id: string;
        token_id: string;
    }): Promise<string>;
    createVerifyUserTokenJWT(payload: {
        user_id: string;
    }): Promise<string>;
    createPasswordResetTokenJWT(payload: {
        user: User;
        expires: string;
    }): Promise<string>;
    createAccessTokenPayload: (user: User) => {
        user: User;
        expires: string;
    };
    createRefreshTokenPayload: (user: User) => {
        token_id: string;
        user_id: string;
        expires: string;
    };
    createVerifyTokenPayload: (user: User) => {
        user_id: string;
    };
    createPasswordResetTokenPayload: (user: User) => {
        token_id: string;
        user: User;
        expires: string;
    };
    findRefreshToken(userId: string, jwtId: string): Promise<RefreshToken>;
    saveRefreshToken(id: string, token: string, user: User): Promise<any>;
    deleteRefreshToken(jwtId: string): Promise<any>;
    findPasswordReset(userId: string, jwtId: string, includeUser?: boolean): Promise<PasswordReset>;
    savePasswordReset(id: string, user: User, status: PASSWORD_RESET_STATUS): Promise<any>;
    updatePasswordReset(id: string, status: PASSWORD_RESET_STATUS): Promise<any>;
    deletePasswordResetToken(jwtId: string): Promise<any>;
    passwordResetIsExpired(createdAt: Date): boolean;
}
