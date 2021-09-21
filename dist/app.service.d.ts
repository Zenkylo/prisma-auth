import { PrismaService } from './prisma.service';
import { User } from '@prisma/client';
export declare class AppService {
    private prisma;
    constructor(prisma: PrismaService);
    getUsers(): Promise<User[]>;
}
