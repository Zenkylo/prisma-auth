"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppModule = void 0;
const common_1 = require("@nestjs/common");
const app_controller_1 = require("./app.controller");
const app_service_1 = require("./app.service");
const prisma_service_1 = require("./prisma.service");
const auth_module_1 = require("./auth/auth.module");
const webAuth_module_1 = require("./web/auth/webAuth.module");
const auth_middleware_1 = require("./middlewares/auth.middleware");
const auth_service_1 = require("./auth/auth.service");
const token_service_1 = require("./token/token.service");
const email_service_1 = require("./email/email.service");
let AppModule = class AppModule {
    configure(consumer) {
        consumer
            .apply(auth_middleware_1.AuthMiddleware)
            .exclude({ path: 'auth/login', method: common_1.RequestMethod.POST }, { path: 'auth/refresh', method: common_1.RequestMethod.GET }, { path: 'auth/verify', method: common_1.RequestMethod.GET }, { path: 'auth/register', method: common_1.RequestMethod.POST }, { path: 'auth/password-reset', method: common_1.RequestMethod.POST }, { path: 'web/auth/login', method: common_1.RequestMethod.GET }, { path: 'web/auth/login', method: common_1.RequestMethod.POST }, { path: 'web/auth/register', method: common_1.RequestMethod.GET }, { path: 'web/auth/register', method: common_1.RequestMethod.POST }, { path: 'web/auth/verify', method: common_1.RequestMethod.GET }, { path: 'web/auth/password-reset', method: common_1.RequestMethod.GET }, { path: 'web/auth/password-reset/capture', method: common_1.RequestMethod.GET }, { path: 'web/auth/password-reset', method: common_1.RequestMethod.POST }, { path: 'web/auth/password-reset-email', method: common_1.RequestMethod.GET }, { path: 'web/auth/password-reset-password', method: common_1.RequestMethod.GET }, { path: 'web/auth/password-reset/capture', method: common_1.RequestMethod.POST }, { path: 'web/auth/password-reset-sent', method: common_1.RequestMethod.GET })
            .forRoutes('/');
    }
};
AppModule = __decorate([
    (0, common_1.Module)({
        imports: [auth_module_1.AuthModule, webAuth_module_1.WebAuthModule],
        controllers: [app_controller_1.AppController],
        providers: [
            app_service_1.AppService,
            prisma_service_1.PrismaService,
            auth_service_1.AuthService,
            token_service_1.TokenService,
            email_service_1.EmailService,
        ],
    })
], AppModule);
exports.AppModule = AppModule;
//# sourceMappingURL=app.module.js.map