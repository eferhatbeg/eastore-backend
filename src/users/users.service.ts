import { Injectable, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { Role } from './entities/role.entity';
import * as bcrypt from 'bcrypt';
@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
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
}
