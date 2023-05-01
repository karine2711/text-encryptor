import { IsString, IsNotEmpty } from 'class-validator';

export class MessageDto {
  @IsNotEmpty()
  @IsString()
  message: string;
}
