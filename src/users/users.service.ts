import { Injectable, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { Role } from './entities/role.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import * as bcrypt from 'bcrypt';
@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>,
  ) {}

  findAll() {
    return this.userRepository.find({ relations: ['roles'] });
  }

  findOne(id: number) {
    return this.userRepository.findOne({
      where: { id },
      relations: ['roles', 'refreshTokens'],
    });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async findByEmailWithRoles(email: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { email },
      relations: ['roles'],
    });
  }

  async register(email: string, password: string): Promise<Partial<User>> {
    const existingUser = await this.findByEmail(email);
    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    const password_hash = await this.hashPassword(password);

    let defaultRole = await this.roleRepository.findOne({
      where: { name: 'USER' },
    });

    if (!defaultRole) {
      defaultRole = this.roleRepository.create({ name: 'USER' });
      await this.roleRepository.save(defaultRole);
    }

    const user = this.userRepository.create({
      email,
      password_hash,
      roles: [defaultRole],
    });

    const savedUser = await this.userRepository.save(user);

    // Remove password_hash from the response
    const { password_hash: _, ...result } = savedUser;
    return result as Partial<User>;
  }

  async hashPassword(password: string): Promise<string> {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
  }

  async comparePasswords(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async storeRefreshToken(
    userId: number,
    refreshToken: string,
    expiresAt: Date,
  ) {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new Error('User not found');
    }

    const tokenHash = await this.hashPassword(refreshToken);

    const tokenEntity = this.refreshTokenRepository.create({
      user,
      token_hash: tokenHash,
      expires_at: expiresAt,
    });

    await this.refreshTokenRepository.save(tokenEntity);
  }

  async validateRefreshToken(
    userId: number,
    refreshToken: string,
  ): Promise<boolean> {
    const tokens = await this.refreshTokenRepository.find({
      where: { user: { id: userId } },
    });

    const now = new Date();
    for (const token of tokens) {
      if (token.revoked_at !== null) continue;
      if (token.expires_at < now) continue;

      const isMatch = await this.comparePasswords(
        refreshToken,
        token.token_hash,
      );
      if (isMatch) return true;
    }
    return false;
  }
}
