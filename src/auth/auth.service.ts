/* eslint-disable no-var */
import { Injectable, HttpException, Response } from '@nestjs/common';
import { LoginAuthDto } from './dto/login-auth.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { PrismaService } from '../prisma.service';
import { Request } from 'express';
import * as dayjs from 'dayjs';
import { PASSWORD_RESET_STATUS, User, VerifyUser } from '.prisma/client';
import { TokenService } from 'src/token/token.service';
import { EmailService } from 'src/email/email.service';
import { ResetPasswordAuthDto } from './dto/reset-password-auth.dto';
const bcrypt = require('bcrypt');

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private tokenService: TokenService,
    private emailService: EmailService,
  ) {}

  /**
   * Login reqeust
   * @param loginAuthDto Object
   * @param loginAuthDto.email String
   * @param loginAuthDto.password String
   * @param response Provided to set a cookie header
   * @returns {Promise}
   */
  async login(
    loginAuthDto: LoginAuthDto,
    response: Response,
  ): Promise<unknown> {
    const email = loginAuthDto.email;
    const password = loginAuthDto.password;

    /**
     * Find User
     */
    try {
      var user = await this.findUserByEmail(email);
    } catch (err) {
      throw new HttpException('invalid login', 400);
    }
    if (!user) throw new HttpException('invalid login', 400);

    /**
     * Test password
     */
    try {
      var passwordValid = await this.passwordMatchesHash(password, user);
    } catch (err) {
      throw new HttpException('bad password', 400);
    }
    if (!passwordValid) throw new HttpException('bad password', 400);
    delete user.password;

    /**
     * Create access and refresh token payloads.
     * The payload is the middle part of the jwt.
     */
    const refreshTokenPayload =
      this.tokenService.createRefreshTokenPayload(user);
    const accessTokenPayload = this.tokenService.createAccessTokenPayload(user);

    /**
     * Create JWTs with payloads
     */
    try {
      var access_token = await this.tokenService.createAccessTokenJWT(
        accessTokenPayload,
      );
      var refresh_token = await this.tokenService.createRefreshTokenJWT(
        refreshTokenPayload,
      );
    } catch (err) {
      console.error('error creating access and refresh tokens', err);
      throw new HttpException('invalid login', 400);
    }

    /**
     * Save the refresh token to database.
     * This will save the JWT as well as additional
     * columns to associate token with a user.
     * Columns: id | userId | token | enabled | createdAt | updatedAt
     */
    try {
      await this.tokenService.saveRefreshToken(
        refreshTokenPayload.token_id,
        refresh_token,
        user,
      );
    } catch (err) {
      throw new HttpException('invalid login', 400);
    }

    /**
     * Set the refresh JWT to response cookie.
     * Expires same time as token.
     * http only. samesite true.
     */
    this.setRefreshTokenCookieInResponse(
      response,
      refresh_token,
      refreshTokenPayload.expires,
    );
    return { user, access_token };
  }

  async verifyUser(token: string): Promise<unknown> {
    try {
      var verifyTokenJwt = await this.tokenService.decodeVerifyUserToken(token);
    } catch (err) {
      throw new HttpException('invalid token', 400);
    }

    const userId = verifyTokenJwt['user_id'];

    try {
      var verifyUserRecord = await this.findVerifyUser(userId);
    } catch (err) {
      throw new HttpException('invalid token', 400);
    }

    const user: User = verifyUserRecord['user'];

    if (!user) throw new HttpException('user not found', 400);
    if (user.id !== userId) throw new HttpException('invalid user', 400);

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
    } catch (err) {
      throw new HttpException('invalid token', 400);
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
    } catch (err) {
      throw new HttpException('invalid token', 400);
    }

    return { user };
  }

  async register(
    registerAuthDto: RegisterAuthDto,
    response: Response,
  ): Promise<unknown> {
    try {
      var passwordHash = await bcrypt.hash(registerAuthDto.password, 10);
    } catch (err) {
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
    } catch (err) {
      throw new HttpException('error creating user', 400);
    }

    delete registeredUser['password'];

    try {
      await this.prisma.verifyUser.create({
        data: {
          userId: registeredUser.id,
          status: 'PENDING',
        },
      })
    } catch (err) {
      console.error('error creating verify user record')
    }

    const verifyUserTokenPayload =
      this.tokenService.createVerifyTokenPayload(registeredUser);
    const refreshTokenPayload = this.tokenService.createRefreshTokenPayload(registeredUser);
    const accessTokenPayload = this.tokenService.createAccessTokenPayload(registeredUser);

    /**
     * Create JWTs with payloads
     */
     try {
      var access_token = await this.tokenService.createAccessTokenJWT(
        accessTokenPayload,
      );
      var refresh_token = await this.tokenService.createRefreshTokenJWT(
        refreshTokenPayload,
      );
      var verify_token = await this.tokenService.createVerifyUserTokenJWT(
        verifyUserTokenPayload,
      );
    } catch (err) {
      console.error('error creating access and refresh tokens', err);
      throw new HttpException('invalid login', 400);
    }

    // TODO Won't be in response but in async email body.
    const verifyLink = this.buildVerifyUserUrl(verify_token);

    /**
     * Save the refresh token to database.
     * This will save the JWT as well as additional
     * columns to associate token with a user.
     * Columns: id | userId | token | enabled | createdAt | updatedAt
     */
    try {
      await this.tokenService.saveRefreshToken(
        refreshTokenPayload.token_id,
        refresh_token,
        registeredUser,
      );
    } catch (err) {
      throw new HttpException('invalid login', 400);
    }

    try {
      await this.emailService.sendVerificationEmail(user.email, verifyLink);
    } catch (err) {
      console.error('error sending email', err);
    }

    /**
     * Set the refresh JWT to response cookie.
     * Expires same time as token.
     * http only. samesite true.
     */
    this.setRefreshTokenCookieInResponse(
      response,
      refresh_token,
      refreshTokenPayload.expires,
    );
    return { user: registeredUser, access_token, __verify_url: verifyLink };
  }

  async reverify(id: string): Promise<unknown> {
    const userId = id;
    return await this.prisma.verifyUser.create({
      data: {
        userId: userId,
        status: 'PENDING',
      },
    });
  }

  async refreshToken(request: Request, response: Response): Promise<unknown> {
    const refreshToken = request['cookies'].refresh_token;

    try {
      var refreshJwt = await this.tokenService.decodeRefreshToken(refreshToken);
    } catch (err) {
      throw new HttpException('token invalid', 400);
    }

    // if now is after validToken.expires
    if (dayjs().isAfter(dayjs(refreshJwt['expires'])))
      throw new HttpException('token expired', 400);

    const refreshJwtUserId = refreshJwt['user_id'];
    const refreshJwtId = refreshJwt['token_id'];

    try {
      var savedRefreshToken = await this.tokenService.findRefreshToken(
        refreshJwtUserId,
        refreshJwtId,
      );
    } catch (err) {
      throw new HttpException('token invalid', 400);
    }

    // Lack of savedRefreshToken does not throw an error
    if (!savedRefreshToken) throw new HttpException('token invalid', 400);

    if (!savedRefreshToken.enabled)
      throw new HttpException('token disabled', 400);

    const user = savedRefreshToken['user'];
    delete user['password'];

    const decodedSavedRefreshToken = await this.tokenService.decodeRefreshToken(
      savedRefreshToken['token'],
    );

    if (refreshJwtUserId !== decodedSavedRefreshToken['user_id'])
      throw new HttpException('token invalid', 400);

    try {
      await this.tokenService.deleteRefreshToken(refreshJwtId);
    } catch (err) {
      console.error('Error deleting refresh token. Continuing though...');
    }

    const refreshTokenPayload = this.tokenService.createRefreshTokenPayload(user);
    const accessTokenPayload = this.tokenService.createAccessTokenPayload(user);

    /**
     * Create JWTs with payloads
     */
     try {
      var access_token = await this.tokenService.createAccessTokenJWT(
        accessTokenPayload,
      );
      var refresh_token = await this.tokenService.createRefreshTokenJWT(
        refreshTokenPayload,
      );
    } catch (err) {
      console.error('error creating access and refresh tokens', err);
      throw new HttpException('invalid login', 400);
    }

    /**
     * Save the refresh token to database.
     * This will save the JWT as well as additional
     * columns to associate token with a user.
     * Columns: id | userId | token | enabled | createdAt | updatedAt
     */
    try {
      await this.tokenService.saveRefreshToken(
        refreshTokenPayload.token_id,
        refresh_token,
        user,
      );
    } catch (err) {
      throw new HttpException('invalid login', 400);
    }

    /**
     * Set the refresh JWT to response cookie.
     * Expires same time as token.
     * http only. samesite true.
     */
    this.setRefreshTokenCookieInResponse(
      response,
      refresh_token,
      refreshTokenPayload.expires,
    );
    return { user, access_token };
  }

  async getMe(request: Request): Promise<unknown> {
    const accessToken = this.getBearerTokenFromRequest(request);
    if (!accessToken) throw new HttpException('invalid user', 401);

    try {
      var decodedAccessToken = await this.tokenService.decodeAccessToken(
        accessToken,
      );
      var userId = decodedAccessToken['id'];
      var user = await this.prisma.user.findFirst({ where: { id: userId } });
    } catch (err) {
      throw new HttpException('unauthorized resource', 401);
    }

    delete user['password'];
    return user;
  }

  async createPasswordReset(request: Request): Promise<unknown> {
    const email = request.body.email;

    try {
      var user = await this.findUserByEmail(email);
    } catch (err) {
      console.log(
        `password reset issued for email that doesnt exist. email: ${email}`,
      );
      return { email }
    }

    if (!user) {
      return { email }
    }

    delete user.password;
    var passwordResetTokenPayload =
      this.tokenService.createPasswordResetTokenPayload(user);

    try {
      var passwordResetJwt =
        await this.tokenService.createPasswordResetTokenJWT(
          passwordResetTokenPayload,
        );
      var passwordReset = await this.tokenService.savePasswordReset(
        passwordResetTokenPayload['token_id'],
        user,
        PASSWORD_RESET_STATUS.PENDING,
      );
    } catch (err) {
      console.error(err);
      return { email }
    }

    const passwordResetUrl = this.buildPasswordResetUrl(passwordResetJwt);

    try {
      await this.emailService.sendPasswordResetEmail(
        user.email,
        passwordResetUrl,
      );
    } catch (err) {
      console.error('error sending email', err);
      return { email }
    }

    return {
      email,
      // passwordResetJwt,
      // passwordReset,
      // __passwordResetUrl: passwordResetUrl,
    };
  }

  async getPasswordReset(token: string): Promise<unknown> {
    const decodedPasswordResetToken =
      await this.tokenService.decodePasswordResetToken(token);
    if (!decodedPasswordResetToken)
      throw new HttpException('invalid password reset', 400);

    const email = decodedPasswordResetToken['user']['email']

    try {
      var passwordReset = await this.tokenService.findPasswordReset(
        decodedPasswordResetToken['user']['id'],
        decodedPasswordResetToken['token_id'],
      );
    } catch (err) {
      throw new HttpException('password reset not found', 400);
    }

    if (this.tokenService.passwordResetIsExpired(passwordReset.createdAt))
      throw new HttpException('password reset expired', 400);

    return { token, passwordReset, email };
  }

  async updatePassword(
    token: string,
    resetPassAuthDto: ResetPasswordAuthDto,
  ): Promise<unknown> {
    const decodedPasswordResetToken =
      await this.tokenService.decodePasswordResetToken(token);
    if (!decodedPasswordResetToken)
      throw new HttpException('invalid password reset', 400);
    try {
      var passwordReset = await this.tokenService.findPasswordReset(
        decodedPasswordResetToken['user']['id'],
        decodedPasswordResetToken['token_id'],
        true,
      );
    } catch (err) {
      throw new HttpException('invalid password reset', 400);
    }

    if (passwordReset.status === PASSWORD_RESET_STATUS.ACCEPTED)
      throw new HttpException('password reset already accepted', 400);

    if (passwordReset.status === PASSWORD_RESET_STATUS.EXPIRED)
      throw new HttpException('password reset expired', 400);

    if (this.tokenService.passwordResetIsExpired(passwordReset.createdAt))
      throw new HttpException('password reset expired', 400);

    try {
      var passwordHash = await bcrypt.hash(resetPassAuthDto['password'], 10);
    } catch (err) {
      throw Error(err);
    }

    passwordReset['user']['password'] = passwordHash;

    try {
      var updatedUser = await this.updateUser(
        passwordReset['user']['id'],
        passwordReset['user'],
      );
    } catch (err) {
      console.error('error updating users password', err);
      throw new HttpException('error updating password', 400);
    }

    delete updatedUser.password;

    try {
      await this.tokenService.updatePasswordReset(
        passwordReset.id,
        PASSWORD_RESET_STATUS.ACCEPTED,
      );
    } catch (err) {
      console.error(
        'error updating password reset. continuing though as users password updated.',
      );
    }

    return updatedUser;

  }

  async validateRequest(req: Request): Promise<string> {
    const accessToken = this.getBearerTokenFromRequest(req);
    return await this.tokenService.decodeAccessToken(accessToken);
  }

  private getBearerTokenFromRequest = (req: Request): string => {
    if (!req.headers) return '';
    if (!req.headers.authorization) return '';

    try {
      var token = req.headers.authorization;
      return token.split('Bearer ')[1];
    } catch (err) {
      return '';
    }
  };

  /**
   * Private members
   */

  // TODO put in user service when created
  private async findUserByEmail(email: string): Promise<User> {
    return await this.prisma.user.findFirst({ where: { email } });
  }

  private async findVerifyUser(userId: string): Promise<VerifyUser> {
    return await this.prisma.verifyUser.findFirst({
      where: { userId },
      include: { user: true },
    });
  }

  // TODO put in user service when created
  private async findUserById(id: string): Promise<User> {
    return await this.prisma.user.findFirst({ where: { id } });
  }

  // TODO put in user service when created
  private async updateUser(id: string, user: User): Promise<User> {
    return await this.prisma.user.update({
      where: {
        id: user['id'],
      },
      data: {
        password: user['password'],
      }
    })
  }

  private buildVerifyUserUrl = (token: string): string => {
    return `${process.env.SERVER_HOST}/web/auth/verify?token=${token}`;
  };

  private buildPasswordResetUrl = (token: string): string => {
    return `${process.env.SERVER_HOST}/web/auth/password-reset/capture?token=${token}`;
  };

  private async passwordMatchesHash(
    password: string,
    user: User,
  ): Promise<boolean> {
    return await bcrypt.compare(password, user.password);
  }

  private setRefreshTokenCookieInResponse(
    res: Response,
    token: string,
    expires: string,
  ): void {
    res['cookie']('refresh_token', token, {
      expires: new Date(expires),
      sameSite: 'strict',
      httpOnly: true,
    });
  }
}
