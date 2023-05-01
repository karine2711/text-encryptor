import { BadRequestException, Controller, Get, Query } from '@nestjs/common';
import { MessageDto } from '../../dtos/message.dto';
import { BlowfishService } from './blowfish.service';

@Controller('blowfish')
export class BlowfishController {
  constructor(private readonly blowFishService: BlowfishService) {}

  @Get('encrypt')
  encryptBlowfish(@Query() { message }: MessageDto): string {
    return this.blowFishService.encrypt(message);
  }

  @Get('decrypt')
  decryptBlowfish(@Query() { message }: MessageDto): string {
    let parsedMessage: string;
    try {
      parsedMessage = JSON.parse(message);
    } catch {
      throw new BadRequestException(
        'message must be surrounded with double quotes',
      );
    }
    return this.blowFishService.decrypt(parsedMessage);
  }
}
