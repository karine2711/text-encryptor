import { Body, Controller, Post } from '@nestjs/common';
import { MessageDto } from '../../dtos/message.dto';
import { RsaService } from './rsa.service';

@Controller('rsa')
export class RsaController {
  constructor(private readonly rsaService: RsaService) {}

  @Post('encrypt')
  encryptRsa(@Body() { message }: MessageDto): string {
    return this.rsaService.encrypt(message);
  }

  @Post('decrypt')
  decryptRsa(@Body() { message }: MessageDto): string {
    return this.rsaService.decrypt(message);
  }
}
