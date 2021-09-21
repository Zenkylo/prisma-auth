"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const prisma_service_1 = require("../prisma.service");
const dayjs = require("dayjs");
const client_1 = require(".prisma/client");
const token_service_1 = require("../token/token.service");
const email_service_1 = require("../email/email.service");
const bcrypt = require('bcrypt');
let AuthService = class AuthService {
    constructor(prisma, tokenService, emailService) {
        this.prisma = prisma;
        this.tokenService = tokenService;
        this.emailService = emailService;
        this.getBearerTokenFromRequest = (req) => {
            if (!req.headers)
                return '';
            if (!req.headers.authorization)
                return '';
            try {
                var token = req.headers.authorization;
                return token.split('Bearer ')[1];
            }
            catch (err) {
                return '';
            }
        };
        this.buildVerifyUserUrl = (token) => {
            return `${process.env.SERVER_HOST}/web/auth/verify?token=${token}`;
        };
        this.buildPasswordResetUrl = (token) => {
            return `${process.env.SERVER_HOST}/web/auth/password-reset/capture?token=${token}`;
        };
    }
    async login(loginAuthDto, response) {
        const email = loginAuthDto.email;
        const password = loginAuthDto.password;
        try {
            var user = await this.findUserByEmail(email);
        }
        catch (err) {
            throw new common_1.HttpException('invalid login', 400);
        }
        if (!user)
            throw new common_1.HttpException('invalid login', 400);
        try {
            var passwordValid = await this.passwordMatchesHash(password, user);
        }
        catch (err) {
            throw new common_1.HttpException('bad password', 400);
        }
        if (!passwordValid)
            throw new common_1.HttpException('bad password', 400);
        delete user.password;
        const refreshTokenPayload = this.tokenService.createRefreshTokenPayload(user);
        const accessTokenPayload = this.tokenService.createAccessTokenPayload(user);
        try {
            var access_token = await this.tokenService.createAccessTokenJWT(accessTokenPayload);
            var refresh_token = await this.tokenService.createRefreshTokenJWT(refreshTokenPayload);
        }
        catch (err) {
            console.error('error creating access and refresh tokens', err);
            throw new common_1.HttpException('invalid login', 400);
        }
        try {
            await this.tokenService.saveRefreshToken(refreshTokenPayload.token_id, refresh_token, user);
        }
        catch (err) {
            throw new common_1.HttpException('invalid login', 400);
        }
        this.setRefreshTokenCookieInResponse(response, refresh_token, refreshTokenPayload.expires);
        return { user, access_token };
    }
    async verifyUser(token) {
        try {
            var verifyTokenJwt = await this.tokenService.decodeVerifyUserToken(token);
        }
        catch (err) {
            throw new common_1.HttpException('invalid token', 400);
        }
        const userId = verifyTokenJwt['user_id'];
        try {
            var verifyUserRecord = await this.findVerifyUser(userId);
        }
        catch (err) {
            throw new common_1.HttpException('invalid token', 400);
        }
        const user = verifyUserRecord['user'];
        if (!user)
            throw new common_1.HttpException('user not found', 400);
        if (user.id !== userId)
            throw new common_1.HttpException('invalid user', 400);
        delete user.password;
        try {
            await this.prisma.verifyUser.update({
                where: {
                    id: verifyUserRecord.id,
                },
                data: {
                    status: 'ACCEPTED',
                },
            });
        }
        catch (err) {
            throw new common_1.HttpException('invalid token', 400);
        }
        try {
            await this.prisma.user.update({
                where: {
                    id: user.id,
                },
                data: {
                    verified: true,
                },
            });
        }
        catch (err) {
            throw new common_1.HttpException('invalid token', 400);
        }
        return { user };
    }
    async register(registerAuthDto, response) {
        try {
            var passwordHash = await bcrypt.hash(registerAuthDto.password, 10);
        }
        catch (err) {
            throw Error(err);
        }
        const user = {
            email: registerAuthDto.email,
            password: passwordHash,
            enabled: true,
            verified: false,
        };
        console.log(user);
        try {
            var registeredUser = await this.prisma.user.create({ data: user });
        }
        catch (err) {
            throw new common_1.HttpException('error creating user', 400);
        }
        delete registeredUser['password'];
        try {
            await this.prisma.verifyUser.create({
                data: {
                    userId: registeredUser.id,
                    status: 'PENDING',
                },
            });
        }
        catch (err) {
            console.error('error creating verify user record');
        }
        const verifyUserTokenPayload = this.tokenService.createVerifyTokenPayload(registeredUser);
        const refreshTokenPayload = this.tokenService.createRefreshTokenPayload(registeredUser);
        const accessTokenPayload = this.tokenService.createAccessTokenPayload(registeredUser);
        try {
            var access_token = await this.tokenService.createAccessTokenJWT(accessTokenPayload);
            var refresh_token = await this.tokenService.createRefreshTokenJWT(refreshTokenPayload);
            var verify_token = await this.tokenService.createVerifyUserTokenJWT(verifyUserTokenPayload);
        }
        catch (err) {
            console.error('error creating access and refresh tokens', err);
            throw new common_1.HttpException('invalid login', 400);
        }
        const verifyLink = this.buildVerifyUserUrl(verify_token);
        try {
            await this.tokenService.saveRefreshToken(refreshTokenPayload.token_id, refresh_token, registeredUser);
        }
        catch (err) {
            throw new common_1.HttpException('invalid login', 400);
        }
        try {
            await this.emailService.sendVerificationEmail(user.email, verifyLink);
        }
        catch (err) {
            console.error('error sending email', err);
        }
        this.setRefreshTokenCookieInResponse(response, refresh_token, refreshTokenPayload.expires);
        return { user: registeredUser, access_token, __verify_url: verifyLink };
    }
    async reverify(id) {
        const userId = id;
        return await this.prisma.verifyUser.create({
            data: {
                userId: userId,
                status: 'PENDING',
            },
        });
    }
    async refreshToken(request, response) {
        const refreshToken = request['cookies'].refresh_token;
        try {
            var refreshJwt = await this.tokenService.decodeRefreshToken(refreshToken);
        }
        catch (err) {
            throw new common_1.HttpException('token invalid', 400);
        }
        if (dayjs().isAfter(dayjs(refreshJwt['expires'])))
            throw new common_1.HttpException('token expired', 400);
        const refreshJwtUserId = refreshJwt['user_id'];
        const refreshJwtId = refreshJwt['token_id'];
        try {
            var savedRefreshToken = await this.tokenService.findRefreshToken(refreshJwtUserId, refreshJwtId);
        }
        catch (err) {
            throw new common_1.HttpException('token invalid', 400);
        }
        if (!savedRefreshToken)
            throw new common_1.HttpException('token invalid', 400);
        if (!savedRefreshToken.enabled)
            throw new common_1.HttpException('token disabled', 400);
        const user = savedRefreshToken['user'];
        delete user['password'];
        const decodedSavedRefreshToken = await this.tokenService.decodeRefreshToken(savedRefreshToken['token']);
        if (refreshJwtUserId !== decodedSavedRefreshToken['user_id'])
            throw new common_1.HttpException('token invalid', 400);
        try {
            await this.tokenService.deleteRefreshToken(refreshJwtId);
        }
        catch (err) {
            console.error('Error deleting refresh token. Continuing though...');
        }
        const refreshTokenPayload = this.tokenService.createRefreshTokenPayload(user);
        const accessTokenPayload = this.tokenService.createAccessTokenPayload(user);
        try {
            var access_token = await this.tokenService.createAccessTokenJWT(accessTokenPayload);
            var refresh_token = await this.tokenService.createRefreshTokenJWT(refreshTokenPayload);
        }
        catch (err) {
            console.error('error creating access and refresh tokens', err);
            throw new common_1.HttpException('invalid login', 400);
        }
        try {
            await this.tokenService.saveRefreshToken(refreshTokenPayload.token_id, refresh_token, user);
        }
        catch (err) {
            throw new common_1.HttpException('invalid login', 400);
        }
        this.setRefreshTokenCookieInResponse(response, refresh_token, refreshTokenPayload.expires);
        return { user, access_token };
    }
    async getMe(request) {
        const accessToken = this.getBearerTokenFromRequest(request);
        if (!accessToken)
            throw new common_1.HttpException('invalid user', 401);
        try {
            var decodedAccessToken = await this.tokenService.decodeAccessToken(accessToken);
            var userId = decodedAccessToken['id'];
            var user = await this.prisma.user.findFirst({ where: { id: userId } });
        }
        catch (err) {
            throw new common_1.HttpException('unauthorized resource', 401);
        }
        delete user['password'];
        return user;
    }
    async createPasswordReset(request) {
        const email = request.body.email;
        try {
            var user = await this.findUserByEmail(email);
        }
        catch (err) {
            console.log(`password reset issued for email that doesnt exist. email: ${email}`);
            return { email };
        }
        if (!user) {
            return { email };
        }
        delete user.password;
        var passwordResetTokenPayload = this.tokenService.createPasswordResetTokenPayload(user);
        try {
            var passwordResetJwt = await this.tokenService.createPasswordResetTokenJWT(passwordResetTokenPayload);
            var passwordReset = await this.tokenService.savePasswordReset(passwordResetTokenPayload['token_id'], user, client_1.PASSWORD_RESET_STATUS.PENDING);
        }
        catch (err) {
            console.error(err);
            return { email };
        }
        const passwordResetUrl = this.buildPasswordResetUrl(passwordResetJwt);
        try {
            await this.emailService.sendPasswordResetEmail(user.email, passwordResetUrl);
        }
        catch (err) {
            console.error('error sending email', err);
            return { email };
        }
        return {
            email,
        };
    }
    async getPasswordReset(token) {
        const decodedPasswordResetToken = await this.tokenService.decodePasswordResetToken(token);
        if (!decodedPasswordResetToken)
            throw new common_1.HttpException('invalid password reset', 400);
        const email = decodedPasswordResetToken['user']['email'];
        try {
            var passwordReset = await this.tokenService.findPasswordReset(decodedPasswordResetToken['user']['id'], decodedPasswordResetToken['token_id']);
        }
        catch (err) {
            throw new common_1.HttpException('password reset not found', 400);
        }
        if (this.tokenService.passwordResetIsExpired(passwordReset.createdAt))
            throw new common_1.HttpException('password reset expired', 400);
        return { token, passwordReset, email };
    }
    async updatePassword(token, resetPassAuthDto) {
        const decodedPasswordResetToken = await this.tokenService.decodePasswordResetToken(token);
        if (!decodedPasswordResetToken)
            throw new common_1.HttpException('invalid password reset', 400);
        try {
            var passwordReset = await this.tokenService.findPasswordReset(decodedPasswordResetToken['user']['id'], decodedPasswordResetToken['token_id'], true);
        }
        catch (err) {
            throw new common_1.HttpException('invalid password reset', 400);
        }
        if (passwordReset.status === client_1.PASSWORD_RESET_STATUS.ACCEPTED)
            throw new common_1.HttpException('password reset already accepted', 400);
        if (passwordReset.status === client_1.PASSWORD_RESET_STATUS.EXPIRED)
            throw new common_1.HttpException('password reset expired', 400);
        if (this.tokenService.passwordResetIsExpired(passwordReset.createdAt))
            throw new common_1.HttpException('password reset expired', 400);
        try {
            var passwordHash = await bcrypt.hash(resetPassAuthDto['password'], 10);
        }
        catch (err) {
            throw Error(err);
        }
        passwordReset['user']['password'] = passwordHash;
        try {
            var updatedUser = await this.updateUser(passwordReset['user']['id'], passwordReset['user']);
        }
        catch (err) {
            console.error('error updating users password', err);
            throw new common_1.HttpException('error updating password', 400);
        }
        delete updatedUser.password;
        try {
            await this.tokenService.updatePasswordReset(passwordReset.id, client_1.PASSWORD_RESET_STATUS.ACCEPTED);
        }
        catch (err) {
            console.error('error updating password reset. continuing though as users password updated.');
        }
        return updatedUser;
    }
    async validateRequest(req) {
        const accessToken = this.getBearerTokenFromRequest(req);
        return await this.tokenService.decodeAccessToken(accessToken);
    }
    async findUserByEmail(email) {
        return await this.prisma.user.findFirst({ where: { email } });
    }
    async findVerifyUser(userId) {
        return await this.prisma.verifyUser.findFirst({
            where: { userId },
            include: { user: true },
        });
    }
    async findUserById(id) {
        return await this.prisma.user.findFirst({ where: { id } });
    }
    async updateUser(id, user) {
        return await this.prisma.user.update({
            where: {
                id: user['id'],
            },
            data: {
                password: user['password'],
            }
        });
    }
    async passwordMatchesHash(password, user) {
        return await bcrypt.compare(password, user.password);
    }
    setRefreshTokenCookieInResponse(res, token, expires) {
        res['cookie']('refresh_token', token, {
            expires: new Date(expires),
            sameSite: 'strict',
            httpOnly: true,
        });
    }
};
AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        token_service_1.TokenService,
        email_service_1.EmailService])
], AuthService);
exports.AuthService = AuthService;
//# sourceMappingURL=auth.service.js.map