/* eslint-disable no-var */
import { User } from '.prisma/client';
import { Injectable } from '@nestjs/common';
const AWS = require('aws-sdk');

const SES_CONFIG = {
  accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY,
  region: 'us-east-1',
};

const AWS_SES = new AWS.SES(SES_CONFIG);

@Injectable()
export class EmailService {
  async sendVerificationEmail(recipientEmail: string, link: string): Promise<unknown> {
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

  async sendPasswordResetEmail(
    recipientEmail: string,
    link: string,
  ): Promise<unknown> {
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
}
