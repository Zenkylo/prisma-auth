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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WebAuthController = void 0;
const common_1 = require("@nestjs/common");
const auth_service_1 = require("../../auth/auth.service");
const login_auth_dto_1 = require("../../auth/dto/login-auth.dto");
const register_auth_dto_1 = require("../../auth/dto/register-auth.dto");
const reset_password_auth_dto_1 = require("../../auth/dto/reset-password-auth.dto");
let WebAuthController = class WebAuthController {
    constructor(authService) {
        this.authService = authService;
    }
    renderAuthLogin() { }
    create(loginAuthDto, response) {
        return this.authService.login(loginAuthDto, response);
    }
    renderAuthRegister() { }
    async register(registerAuthDto, response) {
        return await this.authService.register(registerAuthDto, response);
    }
    renderAuthPasswordResetEmail() { }
    async createPasswordReset(request) {
        return await this.authService.createPasswordReset(request);
    }
    async renderAuthPasswordResetPassword(token) {
        return await this.authService.getPasswordReset(token);
    }
    async renderAuthPasswordResetPasswordSuccess(token, resetPassAuthDto) {
        return await this.authService.updatePassword(token, resetPassAuthDto);
    }
    async verifyUser(token) {
        return await this.authService.verifyUser(token);
    }
};
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Get)('auth/login'),
    (0, common_1.Render)('auth/login'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], WebAuthController.prototype, "renderAuthLogin", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Post)('auth/login'),
    (0, common_1.Render)('auth/user'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [login_auth_dto_1.LoginAuthDto, Object]),
    __metadata("design:returntype", void 0)
], WebAuthController.prototype, "create", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Get)('auth/register'),
    (0, common_1.Render)('auth/register'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], WebAuthController.prototype, "renderAuthRegister", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Post)('auth/register'),
    (0, common_1.Render)('auth/user'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [register_auth_dto_1.RegisterAuthDto, Object]),
    __metadata("design:returntype", Promise)
], WebAuthController.prototype, "register", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Get)('auth/password-reset'),
    (0, common_1.Render)('auth/password-reset-email'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], WebAuthController.prototype, "renderAuthPasswordResetEmail", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Post)('auth/password-reset'),
    (0, common_1.Render)('auth/password-reset-sent'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], WebAuthController.prototype, "createPasswordReset", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Get)('auth/password-reset/capture'),
    (0, common_1.Render)('auth/password-reset-password'),
    __param(0, (0, common_1.Query)('token')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], WebAuthController.prototype, "renderAuthPasswordResetPassword", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Post)('auth/password-reset/capture'),
    (0, common_1.Render)('auth/password-reset-success'),
    __param(0, (0, common_1.Query)('token')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, reset_password_auth_dto_1.ResetPasswordAuthDto]),
    __metadata("design:returntype", Promise)
], WebAuthController.prototype, "renderAuthPasswordResetPasswordSuccess", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Get)('auth/verify'),
    (0, common_1.Render)('auth/verify'),
    __param(0, (0, common_1.Query)('token')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], WebAuthController.prototype, "verifyUser", null);
WebAuthController = __decorate([
    (0, common_1.Controller)('web'),
    __metadata("design:paramtypes", [auth_service_1.AuthService])
], WebAuthController);
exports.WebAuthController = WebAuthController;
//# sourceMappingURL=webAuth.controller.js.map