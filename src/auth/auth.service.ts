import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { User } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { UserEntity } from 'src/user/entities/user.entity';
import { UserModel } from 'src/user/user.model';
import { Logger } from 'nestjs-pino';
@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly logger: Logger,
  ) {}

  private verifyToken(refToken: string): [pyaload: User, error: Error] {
    try {
      const payload = this.jwtService.verify<User>(refToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });
      return [payload, null];
    } catch (error) {
      return [null, error];
    }
  }
  async refreshToken(req: Request, res: Response): Promise<string> {
    try {
      const refToken = req?.cookies['refresh_token'];
      if (!refToken) throw new Error('No token found');
      const [payload, error] = this.verifyToken(refToken);
      if (error) throw new Error('Invalid or expired refresh token');
      const userExists = this.prismaService.user.findUnique({
        where: { id: payload.id },
      });
      if (!userExists) throw new Error('Invalid token provided');
      const expiresIn = 15000;
      const exp = Math.floor(Date.now() / 1000) + expiresIn;
      const accessToken = this.jwtService.sign(
        { ...payload, exp },
        {
          secret: this.configService.get('JWT_SECRET'),
        },
      );
      res.cookie('access_token', accessToken, { httpOnly: true });
      return accessToken;
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException(error.message);
    }
  }
  async validateUser(loginUserDto: LoginUserDto): Promise<[Error, UserModel]> {
    try {
      const user = await this.prismaService.user.findUnique({
        where: { email: loginUserDto.email },
      });
      if (!user) throw new Error('User not found');
      const isVerifiedUser = await bcrypt.compare(
        loginUserDto.password,
        user.password,
      );
      if (!isVerifiedUser) throw new Error('Invalid credentials');
      return [null, user];
    } catch (error: any) {
      return [error.message, null];
    }
  }
  private async issueTokens(user: UserModel, response: Response) {
    const payload = { username: user.fullName, sub: user.id };

    const accessToken = this.jwtService.sign(
      { ...payload },
      {
        secret: this.configService.get('JWT_ACCESS_SECRET'),
        expiresIn: this.configService.get('JWT_EXP'),
      },
    );
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
      expiresIn: '7d',
    });
    response.cookie('refresh_token', refreshToken, { httpOnly: true });
    response.cookie('access_token', accessToken, { httpOnly: true });
  }

  async createUser(createUserDto: CreateUserDto, response: Response) {
    try {
      const isExistingUser = this.prismaService.user.findUnique({
        where: { email: createUserDto.email },
      });
      if (isExistingUser) throw new Error('Email already in use');
      const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
      const data = new UserEntity({
        ...createUserDto,
        password: hashedPassword,
      });
      const user = await this.prismaService.user.create({
        data,
      });
      this.issueTokens(user, response);
      return { message: 'User has been created succesfully', status: 201 };
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }
  async loginUser(loginUserDto: LoginUserDto, response: Response) {
    try {
      const [err, user] = await this.validateUser(loginUserDto);
      if (err) throw new Error(err.message);
      this.issueTokens(user, response);
      return { message: 'User logged in successfully', status: 200 };
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }
  async logoutUser(res: Response) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return { message: 'User logged out successfully', status: 200 };
  }
}
