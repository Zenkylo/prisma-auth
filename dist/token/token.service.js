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
exports.TokenService = void 0;
const dayjs = require("dayjs");
const uuid_1 = require("uuid");
const jwt = require('jsonwebtoken');
const prisma_service_1 = require("../prisma.service");
const common_1 = require("@nestjs/common");
let TokenService = class TokenService {
    constructor(prisma) {
        this.prisma = prisma;
        this.ACCESS_TOKEN_EXPIRES_MINUTES = 5;
        this.ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_TOKEN_SECRET;
        this.REFRESH_TOKEN_EXPIRES_MINUTES = 10;
        this.REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_TOKEN_SECRET;
        this.VERIFY_USER_TOKEN_SECRET = process.env.JWT_VERIFY_USER_TOKEN_SECRET;
        this.PASSWORD_RESET_TOKEN_EXPIRES_MINUTES = 1440;
        this.PASSWORD_RESET_TOKEN_SECRET = process.env.JWT_PASSWORD_RESET_TOKEN_SECRET;
        this.createAccessTokenPayload = (user) => {
            return {
                user,
                expires: dayjs()
                    .add(this.ACCESS_TOKEN_EXPIRES_MINUTES, 'minutes')
                    .format(),
            };
        };
        this.createRefreshTokenPayload = (user) => {
            return {
                token_id: (0, uuid_1.v4)(),
                user_id: user.id,
                expires: dayjs()
                    .add(this.REFRESH_TOKEN_EXPIRES_MINUTES, 'minutes')
                    .format(),
            };
        };
        this.createVerifyTokenPayload = (user) => {
            return {
                user_id: user.id,
            };
        };
        this.createPasswordResetTokenPayload = (user) => {
            return {
                token_id: (0, uuid_1.v4)(),
                user,
                expires: dayjs()
                    .add(this.PASSWORD_RESET_TOKEN_EXPIRES_MINUTES, 'minutes')
                    .format(),
            };
        };
    }
    async decodeAccessToken(token) {
        return await jwt.verify(token, this.ACCESS_TOKEN_SECRET);
    }
    async decodeRefreshToken(token) {
        return await jwt.verify(token, this.REFRESH_TOKEN_SECRET);
    }
    async decodeVerifyUserToken(token) {
        return await jwt.verify(token, this.VERIFY_USER_TOKEN_SECRET);
    }
    async decodePasswordResetToken(token) {
        return await jwt.verify(token, this.PASSWORD_RESET_TOKEN_SECRET);
    }
    async createAccessTokenJWT(payload) {
        return await jwt.sign(payload, this.ACCESS_TOKEN_SECRET);
    }
    async createRefreshTokenJWT(payload) {
        return await jwt.sign(payload, this.REFRESH_TOKEN_SECRET);
    }
    async createVerifyUserTokenJWT(payload) {
        return await jwt.sign(payload, this.VERIFY_USER_TOKEN_SECRET);
    }
    async createPasswordResetTokenJWT(payload) {
        return await jwt.sign(payload, this.PASSWORD_RESET_TOKEN_SECRET);
    }
    async findRefreshToken(userId, jwtId) {
        return await this.prisma.refreshToken.findFirst({
            where: {
                id: jwtId,
                userId: userId,
            },
            include: {
                user: true,
            },
        });
    }
    async saveRefreshToken(id, token, user) {
        return this.prisma.refreshToken.create({
            data: {
                id: id,
                userId: user.id,
                token,
                enabled: true,
            },
        });
    }
    async deleteRefreshToken(jwtId) {
        return await this.prisma.refreshToken.delete({
            where: { id: jwtId },
        });
    }
    async findPasswordReset(userId, jwtId, includeUser = false) {
        return await this.prisma.passwordReset.findFirst({
            where: {
                id: jwtId,
                userId: userId,
            },
            include: {
                user: includeUser,
            },
        });
    }
    async savePasswordReset(id, user, status) {
        return this.prisma.passwordReset.create({
            data: {
                id: id,
                userId: user.id,
                status,
            },
        });
    }
    async updatePasswordReset(id, status) {
        return this.prisma.passwordReset.update({
            where: {
                id: id,
            },
            data: {
                status,
            },
        });
    }
    async deletePasswordResetToken(jwtId) {
        return await this.prisma.passwordReset.delete({
            where: { id: jwtId },
        });
    }
    passwordResetIsExpired(createdAt) {
        const now = dayjs();
        const passwordResetCreatedAt = dayjs(createdAt);
        const expiresAt = passwordResetCreatedAt.add(this.PASSWORD_RESET_TOKEN_EXPIRES_MINUTES, 'minutes');
        return now.isAfter(expiresAt);
    }
};
TokenService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService])
], TokenService);
exports.TokenService = TokenService;
//# sourceMappingURL=token.service.js.map