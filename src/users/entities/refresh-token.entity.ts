import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from './user.entity';

@Entity('refresh_tokens')
export class RefreshToken {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, (user) => user.refreshTokens, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column()
  token_hash: string;

  @Column()
  expires_at: Date;

  @Column({ type: 'timestamp', nullable: true })
  revoked_at: Date;

  @CreateDateColumn()
  created_at: Date;

  @Column({ nullable: true })
  user_agent: string;

  @Column({ nullable: true })
  ip_address: string;
}
