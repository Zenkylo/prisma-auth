import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { User, Prisma } from '@prisma/client';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  // @Get()
  // async getUsers(): Promise<User[]> {
  //   return this.appService.getUsers();
  // }
}
