import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { RsaModule } from './modules/rsa/rsa.module';
import { BlowfishModule } from './modules/blowfish/blowfish.module';

@Module({
  imports: [ConfigModule.forRoot(), BlowfishModule, RsaModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
