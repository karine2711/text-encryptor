import { Body, Controller, Post } from '@nestjs/common';
import { MessageDto } from '../../dtos/message.dto';
import { BlowfishService } from './blowfish.service';

@Controller('blowfish')
export class BlowfishController {
  constructor(private readonly blowFishService: BlowfishService) {}

  @Post('encrypt')
  encryptBlowfish(@Body() { message }: MessageDto): string {
    return this.blowFishService.encrypt(message);
  }

  @Post('decrypt')
  decryptBlowfish(@Body() { message }: MessageDto): string {
    return this.blowFishService.decrypt(message);
  }
}
