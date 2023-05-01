import { Module } from '@nestjs/common';
import { BlowfishService } from './blowfish.service';
import { BlowfishController } from './blowfish.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule.forRoot()],
  controllers: [BlowfishController],
  providers: [BlowfishService],
})
export class BlowfishModule {}
