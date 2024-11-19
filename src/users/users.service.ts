import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDTO } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async create({ email, password }: CreateUserDTO) {
    const userExist = await this.findByEmail(email);
    if (userExist) {
      throw new BadRequestException('Email já esta sendo utilizado');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await this.prisma.users.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
  }

  async findByEmail(email: string): Promise<any> {
    return this.prisma.user.findFirst({
      where: {
        email,
      },
    });
  }
}
