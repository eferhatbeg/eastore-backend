import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { User } from './entities/user.entity';
import { Role } from './entities/role.entity';
import { RefreshToken } from './entities/refresh-token.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User, Role, RefreshToken])],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
