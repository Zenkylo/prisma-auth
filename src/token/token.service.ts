import * as dayjs from 'dayjs';
import { v4 as uuid } from 'uuid';
const jwt = require ('jsonwebtoken');
import {
  PasswordReset,
  PASSWORD_RESET_STATUS,
  RefreshToken,
  User,
  VerifyUser,
} from '.prisma/client';
import { PrismaService } from '../prisma.service';
import { Injectable } from '@nestjs/common';

@Injectable()
export class TokenService {
  constructor(private prisma: PrismaService) {}

  private ACCESS_TOKEN_EXPIRES_MINUTES = 5;
  private ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_TOKEN_SECRET;
  private REFRESH_TOKEN_EXPIRES_MINUTES = 10;
  private REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_TOKEN_SECRET;
  private VERIFY_USER_TOKEN_SECRET = process.env.JWT_VERIFY_USER_TOKEN_SECRET;
  private PASSWORD_RESET_TOKEN_EXPIRES_MINUTES = 1440;
  private PASSWORD_RESET_TOKEN_SECRET =
    process.env.JWT_PASSWORD_RESET_TOKEN_SECRET;

  async decodeAccessToken(token: string): Promise<any> {
    return await jwt.verify(token, this.ACCESS_TOKEN_SECRET);
  }

  async decodeRefreshToken(token: string): Promise<any> {
    return await jwt.verify(token, this.REFRESH_TOKEN_SECRET);
  }

  async decodeVerifyUserToken(token: string): Promise<any> {
    return await jwt.verify(token, this.VERIFY_USER_TOKEN_SECRET);
  }

  async decodePasswordResetToken(token: string): Promise<any> {
    return await jwt.verify(token, this.PASSWORD_RESET_TOKEN_SECRET);
  }

  async createAccessTokenJWT(payload: {
    user: User;
    expires: string;
  }): Promise<string> {
    return await jwt.sign(payload, this.ACCESS_TOKEN_SECRET);
  }

  async createRefreshTokenJWT(payload: {
    user_id: string;
    token_id: string;
  }): Promise<string> {
    return await jwt.sign(payload, this.REFRESH_TOKEN_SECRET);
  }

  async createVerifyUserTokenJWT(payload: {
    user_id: string;
  }): Promise<string> {
    return await jwt.sign(payload, this.VERIFY_USER_TOKEN_SECRET);
  }

  async createPasswordResetTokenJWT(payload: {
    user: User;
    expires: string;
  }): Promise<string> {
    return await jwt.sign(payload, this.PASSWORD_RESET_TOKEN_SECRET);
  }

  createAccessTokenPayload = (user: User): { user: User; expires: string } => {
    return {
      user,
      expires: dayjs()
        .add(this.ACCESS_TOKEN_EXPIRES_MINUTES, 'minutes')
        .format(),
    };
  };

  createRefreshTokenPayload = (
    user: User,
  ): { token_id: string; user_id: string; expires: string } => {
    return {
      token_id: uuid(),
      user_id: user.id,
      expires: dayjs()
        .add(this.REFRESH_TOKEN_EXPIRES_MINUTES, 'minutes')
        .format(),
    };
  };

  createVerifyTokenPayload = (user: User): { user_id: string } => {
    return {
      user_id: user.id,
    };
  };

  createPasswordResetTokenPayload = (
    user: User,
  ): { token_id: string; user: User; expires: string } => {
    return {
      token_id: uuid(),
      user,
      expires: dayjs()
        .add(this.PASSWORD_RESET_TOKEN_EXPIRES_MINUTES, 'minutes')
        .format(),
    };
  };

  /**
   * Refresh Tokens
   */
  async findRefreshToken(userId: string, jwtId: string): Promise<RefreshToken> {
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

  async saveRefreshToken(id: string, token: string, user: User): Promise<any> {
    return this.prisma.refreshToken.create({
      data: {
        id: id,
        userId: user.id,
        token,
        enabled: true,
      },
    });
  }

  async deleteRefreshToken(jwtId: string): Promise<any> {
    return await this.prisma.refreshToken.delete({
      where: { id: jwtId },
    });
  }

  /**
   * Password Reset Tokens
   */

  async findPasswordReset(
    userId: string,
    jwtId: string,
    includeUser: boolean = false,
  ): Promise<PasswordReset> {
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

  async savePasswordReset(
    id: string,
    user: User,
    status: PASSWORD_RESET_STATUS,
  ): Promise<any> {
    return this.prisma.passwordReset.create({
      data: {
        id: id,
        userId: user.id,
        status,
      },
    });
  }

  async updatePasswordReset(
    id: string,
    status: PASSWORD_RESET_STATUS,
  ): Promise<any> {
    return this.prisma.passwordReset.update({
      where: {
        id: id,
      },
      data: {
        status,
      },
    });
  }

  async deletePasswordResetToken(jwtId: string): Promise<any> {
    return await this.prisma.passwordReset.delete({
      where: { id: jwtId },
    });
  }

  passwordResetIsExpired(createdAt: Date): boolean {
    const now = dayjs();
    const passwordResetCreatedAt = dayjs(createdAt);
    const expiresAt = passwordResetCreatedAt.add(
      this.PASSWORD_RESET_TOKEN_EXPIRES_MINUTES,
      'minutes',
    );
    return now.isAfter(expiresAt);
  }
}
