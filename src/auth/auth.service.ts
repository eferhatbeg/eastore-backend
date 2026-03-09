import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    return this.usersService.register(registerDto.email, registerDto.password);
  }

  async login(loginDto: LoginDto) {
    const user = await this.usersService.findByEmailWithRoles(loginDto.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.usersService.comparePasswords(
      loginDto.password,
      user.password_hash,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const roles = user.roles ? user.roles.map((role) => role.name) : [];
    const payload = { sub: user.id, email: user.email, roles };

    const access_token = await this.jwtService.signAsync(payload);
    const refresh_token = await this.jwtService.signAsync(
      { sub: user.id },
      { expiresIn: '7d' },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);
    await this.usersService.storeRefreshToken(
      user.id,
      refresh_token,
      expiresAt,
    );

    return {
      access_token,
      refresh_token,
      user: {
        id: user.id,
        email: user.email,
        roles: roles,
      },
    };
  }

  async refreshTokens(refreshToken: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(refreshToken);
      const userId = decoded.sub;

      const isValid = await this.usersService.validateRefreshToken(
        userId,
        refreshToken,
      );
      if (!isValid) {
        throw new UnauthorizedException('Invalid or revoked refresh token');
      }

      const user = await this.usersService.findOne(userId);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const roles = user.roles ? user.roles.map((role) => role.name) : [];
      const payload = { sub: user.id, email: user.email, roles };

      const access_token = await this.jwtService.signAsync(payload);

      return { access_token };
    } catch (e) {
      if (e instanceof UnauthorizedException) {
        throw e;
      }
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }
}
