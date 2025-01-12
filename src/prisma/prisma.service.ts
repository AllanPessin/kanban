import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
    console.log('Connected to prisma');
  }

  async onModuleDestory() {
    await this.$disconnect();
    console.log('Disconnected from prisma');
  }
}
