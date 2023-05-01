import { Controller, Get, Query } from '@nestjs/common';
import { MessageDto } from '../../dtos/message.dto';
import { RsaService } from './rsa.service';

@Controller('rsa')
export class RsaController {
  constructor(private readonly rsaService: RsaService) {}

  @Get('encrypt')
  encryptRsa(@Query() { message }: MessageDto): string {
    return this.rsaService.encrypt(message);
  }

  @Get('decrypt')
  decryptRsa(@Query() { message }: MessageDto): string {
    return this.rsaService.decrypt(message);
  }
}
