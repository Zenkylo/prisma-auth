"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EmailService = void 0;
const common_1 = require("@nestjs/common");
const AWS = require('aws-sdk');
const SES_CONFIG = {
    accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY,
    region: 'us-east-1',
};
const AWS_SES = new AWS.SES(SES_CONFIG);
let EmailService = class EmailService {
    async sendVerificationEmail(recipientEmail, link) {
        const params = {
            Source: 'k4nderson@gmail.com',
            Destination: {
                ToAddresses: [recipientEmail],
            },
            ReplyToAddresses: [],
            Message: {
                Body: {
                    Html: {
                        Charset: 'UTF-8',
                        Data: `
              <h3>Email Verification</h3>
              <p>Please verify your email by following the link below.</p>
              <a href="${link}">${link}</a>
              `,
                    },
                },
                Subject: {
                    Charset: 'UTF-8',
                    Data: `Hello ${recipientEmail}. Please verify your email address.`,
                },
            },
        };
        return await AWS_SES.sendEmail(params).promise();
    }
    async sendPasswordResetEmail(recipientEmail, link) {
        const params = {
            Source: 'k4nderson@gmail.com',
            Destination: {
                ToAddresses: [recipientEmail],
            },
            ReplyToAddresses: [],
            Message: {
                Body: {
                    Html: {
                        Charset: 'UTF-8',
                        Data: `
              <h3>Password Reset</h3>
              <p>Please follow the link below to reset your password.</p>
              <a href="${link}">${link}</a>
              `,
                    },
                },
                Subject: {
                    Charset: 'UTF-8',
                    Data: `Please reset your password for ${recipientEmail}.`,
                },
            },
        };
        return await AWS_SES.sendEmail(params).promise();
    }
};
EmailService = __decorate([
    (0, common_1.Injectable)()
], EmailService);
exports.EmailService = EmailService;
//# sourceMappingURL=email.service.js.map