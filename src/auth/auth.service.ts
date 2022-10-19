import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon2 from 'argon2';
import { Token } from './type';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  hashData(data: string) {
    return argon2.hash(data);
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async getToken(userId: number, email: string): Promise<Token> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'secret',
          expiresIn: 60 * 15,
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'refresh-secret',
          expiresIn: 60 * 60 * 24 * 7,
        },
      ),
    ]);
    return {
      access_token,
      refresh_token,
    };
  }

  async signupLocal(authDto: AuthDto): Promise<Token> {
    const { email, password } = authDto;
    const hash = await this.hashData(password);
    const newUser = await this.prisma.user.create({
      data: {
        email: email,
        hash: hash,
      },
    });

    const tokens = await this.getToken(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);

    return tokens;
  }

  async signinLocal(authDto: AuthDto) {
    const { email, password } = authDto;

    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Access Denied!');
    }

    const passwordMatches = await argon2.verify(user.hash, password);

    if (!passwordMatches) {
      throw new ForbiddenException('Access Denied!');
    }

    const tokens = await this.getToken(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }
  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }
  async refreshTokens(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access Denied!');
    }

    const rtMatches = await argon2.verify(user.hashedRt, rt);

    if (!rtMatches) {
      throw new ForbiddenException('Access Denied!');
    }

    const tokens = await this.getToken(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }
}
