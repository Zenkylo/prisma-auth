import { Controller, Get, Post, Body, Patch, Param, Delete, HttpCode, Header, Req, Response, Res, Query, Put, Render } from '@nestjs/common';
import { AuthService } from 'src/auth/auth.service';
import { LoginAuthDto } from 'src/auth/dto/login-auth.dto';
import { RegisterAuthDto } from 'src/auth/dto/register-auth.dto';
import { ResetPasswordAuthDto } from 'src/auth/dto/reset-password-auth.dto';
import { Request } from 'express';

@Controller('web')
export class WebAuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Render the register page
   */
   @HttpCode(200)
   @Get('auth/login')
   @Render('auth/login')
   renderAuthLogin() {}

  /**
   * Login form
   */
   @HttpCode(200)
   @Post('auth/login')
   @Render('auth/user')
   create(
    @Body() loginAuthDto: LoginAuthDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.login(loginAuthDto, response);
  }

  /**
   * Render the register page
   */
  @HttpCode(200)
  @Get('auth/register')
  @Render('auth/register')
  renderAuthRegister() {}

  /**
   * Capture register form
   */
   @HttpCode(200)
   @Post('auth/register')
   @Render('auth/user')
   async register(
    @Body() registerAuthDto: RegisterAuthDto,
    @Res({ passthrough: true }) response: Response,
  ): Promise<unknown> {
    return await this.authService.register(registerAuthDto, response);
  }

  /**
   * Render the reset password page.
   * This is the start of the reset password flow.
   * The user will provide their email.
   */
   @HttpCode(200)
   @Get('auth/password-reset')
   @Render('auth/password-reset-email')
   renderAuthPasswordResetEmail() {}

  /**
   * Render the reset password sent page.
   * This is a post that takes in the email.
   * It returns the password reset sent page.
   */
   @HttpCode(200)
   @Post('auth/password-reset')
   @Render('auth/password-reset-sent')
   async createPasswordReset(@Req() request: Request): Promise<unknown> {
    return await this.authService.createPasswordReset(request);
  }

  /**
   * Render the reset password page.
   * This is the landing page from the email.
   * The user will provide a new password.
   */
   @HttpCode(200)
   @Get('auth/password-reset/capture')
   @Render('auth/password-reset-password')
  async renderAuthPasswordResetPassword(
    @Query('token') token: string,
  ): Promise<unknown> {
    return await this.authService.getPasswordReset(token);
  }

  /**
   * Accept the updated passwords and render the success page.
   */
   @HttpCode(200)
   @Post('auth/password-reset/capture')
   @Render('auth/password-reset-success')
   async renderAuthPasswordResetPasswordSuccess(
    @Query('token') token: string,
    @Body() resetPassAuthDto: ResetPasswordAuthDto,
  ): Promise<unknown> {
    return await this.authService.updatePassword(token, resetPassAuthDto);
  }

  /**
   * Accept the updated passwords and render the success page.
   */
   @HttpCode(200)
   @Get('auth/verify')
   @Render('auth/verify')
   async verifyUser(@Query('token') token: string): Promise<unknown> {
    return await this.authService.verifyUser(token);
  }
  

}
