import { Controller, Get, Post, Body, Patch, Param, Delete, HttpCode, Header, Req, Response, Res, Query, Put, Render } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginAuthDto } from './dto/login-auth.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResetPasswordAuthDto } from './dto/reset-password-auth.dto';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(200)
  @Post('login')
  create(
    @Body() loginAuthDto: LoginAuthDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.login(loginAuthDto, response);
  }

  @HttpCode(201)
  @Post('register')
  async register(
    @Body() registerAuthDto: RegisterAuthDto,
    @Res({ passthrough: true }) response: Response,
  ): Promise<unknown> {
    return await this.authService.register(registerAuthDto, response);
  }

  @HttpCode(201)
  @Get('refresh')
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<unknown> {
    return await this.authService.refreshToken(request, response);
  }

  @HttpCode(202)
  @Get('verify')
  async verifyUser(@Query('token') token: string): Promise<unknown> {
    return await this.authService.verifyUser(token);
  }

  @HttpCode(200)
  @Get('me')
  async getMe(@Req() request: Request): Promise<unknown> {
    return await this.authService.getMe(request);
  }

  @HttpCode(201)
  @Post('password-reset')
  async createPasswordReset(@Req() request: Request): Promise<unknown> {
    return await this.authService.createPasswordReset(request);
  }

  @HttpCode(200)
  @Get('password-reset')
  async getPasswordReset(@Query('token') token: string): Promise<unknown> {
    return await this.authService.getPasswordReset(token);
  }

  @HttpCode(200)
  @Put('password-reset')
  async updatePassword(
    @Query('token') token: string,
    @Body() resetPassAuthDto: ResetPasswordAuthDto,
  ): Promise<unknown> {
    return await this.authService.updatePassword(token, resetPassAuthDto);
  }

  // Renders
  @HttpCode(200)
  @Get('register')
  @Render('auth/register')
  renderAuthRegister() {
    return { message: 'Hello world!' };
  }

}
