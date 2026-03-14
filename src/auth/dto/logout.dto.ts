import { IsString, IsNotEmpty, IsOptional, IsBoolean } from 'class-validator';

export class LogoutDto {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;

  @IsOptional()
  @IsBoolean()
  revokeAll?: boolean;
}
