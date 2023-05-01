import { Injectable } from '@nestjs/common';
import {
  pArrayConst,
  sBox0Const,
  sBox1Const,
  sBox2Const,
  sBox3Const,
} from './helpers/blowfish-arrays';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class BlowfishService {
  private pArray: number[];
  private sBox0: number[];
  private sBox1: number[];
  private sBox2: number[];
  private sBox3: number[];

  constructor(private readonly configService: ConfigService) {
    const key =
      this.configService.get('BLOWFISH_KEY') || 'uwicb73Jbh83!!$537fvvj73&&821';
    this.pArray = pArrayConst.slice();
    this.sBox0 = sBox0Const.slice();
    this.sBox1 = sBox1Const.slice();
    this.sBox2 = sBox2Const.slice();
    this.sBox3 = sBox3Const.slice();
    this.generateSubkeys(key);
  }

  public encrypt(string: string): string {
    string = this.utf8Decode(string);
    const blocks = Math.ceil(string.length / 8);
    let encryptedString = '';
    for (let i = 0; i < blocks; i++) {
      let block = string.substr(i * 8, 8);
      if (block.length < 8) {
        let count = 8 - block.length;
        while (0 < count--) {
          block += '\0';
        }
      }
      let [xL, xR] = this.split64by32(block);
      [xL, xR] = this.encipher(xL, xR);
      encryptedString += this.num2block32(xL) + this.num2block32(xR);
    }
    return this.safeJsonEncode(encryptedString);
  }

  public decrypt(string: string): string {
    const blocks = Math.ceil(string.length / 8);
    let decryptedString = '';
    for (let i = 0; i < blocks; i++) {
      const block = string.substr(i * 8, 8);
      let [xL, xR] = this.split64by32(block);
      [xL, xR] = this.decipher(xL, xR);
      decryptedString += this.num2block32(xL) + this.num2block32(xR);
    }
    decryptedString = this.utf8Encode(decryptedString);
    decryptedString = this.trimZeros(decryptedString);
    return decryptedString;
  }

  private F(xL: number): number {
    const a = xL >>> 24;
    const b = (xL << 8) >>> 24;
    const c = (xL << 16) >>> 24;
    const d = (xL << 24) >>> 24;
    let res = this.addMod32(this.sBox0[a], this.sBox1[b]);
    res = this.xor(res, this.sBox2[c]);
    res = this.addMod32(res, this.sBox3[d]);
    return res;
  }

  private encipher(xL: number, xR: number): [number, number] {
    for (let i = 0; i < 16; i++) {
      xL = this.xor(xL, this.pArray[i]);
      xR = this.xor(this.F(xL), xR); // Feistel function
      [xL, xR] = [xR, xL];
    }
    [xL, xR] = [xR, xL];
    xR = this.xor(xR, this.pArray[16]);
    xL = this.xor(xL, this.pArray[17]);
    return [xL, xR];
  }

  private decipher(xL: number, xR: number): [number, number] {
    xL = this.xor(xL, this.pArray[17]);
    xR = this.xor(xR, this.pArray[16]);
    [xL, xR] = [xR, xL];
    for (let i = 15; i >= 0; i--) {
      [xL, xR] = [xR, xL];
      xR = this.xor(this.F(xL), xR);
      xL = this.xor(xL, this.pArray[i]);
    }
    return [xL, xR];
  }

  private generateSubkeys(key: string): void {
    let data = 0;
    let k = 0;
    let i: number, j: number;

    for (i = 0; i < 18; i++) {
      for (j = 4; j > 0; j--) {
        data = this.fixNegative((data << 8) | key.charCodeAt(k));
        k = (k + 1) % key.length;
      }
      this.pArray[i] = this.xor(this.pArray[i], data);
      data = 0;
    }

    let block64 = [0, 0];
    for (i = 0; i < 18; i += 2) {
      block64 = this.encipher(block64[0], block64[1]);
      this.pArray[i] = block64[0];
      this.pArray[i + 1] = block64[1];
    }

    for (i = 0; i < 256; i += 2) {
      block64 = this.encipher(block64[0], block64[1]);
      this.sBox0[i] = block64[0];
      this.sBox0[i + 1] = block64[1];
    }

    for (i = 0; i < 256; i += 2) {
      block64 = this.encipher(block64[0], block64[1]);
      this.sBox1[i] = block64[0];
      this.sBox1[i + 1] = block64[1];
    }

    for (i = 0; i < 256; i += 2) {
      block64 = this.encipher(block64[0], block64[1]);
      this.sBox2[i] = block64[0];
      this.sBox2[i + 1] = block64[1];
    }

    for (i = 0; i < 256; i += 2) {
      block64 = this.encipher(block64[0], block64[1]);
      this.sBox3[i] = block64[0];
      this.sBox3[i + 1] = block64[1];
    }
  }

  private block32toNum(block32: string): number {
    return this.fixNegative(
      (block32.charCodeAt(0) << 24) |
        (block32.charCodeAt(1) << 16) |
        (block32.charCodeAt(2) << 8) |
        block32.charCodeAt(3),
    );
  }

  private num2block32(num) {
    return (
      String.fromCharCode(num >>> 24) +
      String.fromCharCode((num << 8) >>> 24) +
      String.fromCharCode((num << 16) >>> 24) +
      String.fromCharCode((num << 24) >>> 24)
    );
  }

  private xor(a: number, b: number) {
    return this.fixNegative(a ^ b);
  }

  private addMod32(a: number, b: number): number {
    return this.fixNegative((a + b) | 0);
  }

  private fixNegative(number: number): number {
    return number >>> 0;
  }

  private split64by32(block64: string): [number, number] {
    const xL = block64.substring(0, 4);
    const xR = block64.substring(4, 8);
    return [this.block32toNum(xL), this.block32toNum(xR)];
  }

  private utf8Decode(string: string): string {
    let utftext = '';
    for (let n = 0; n < string.length; n++) {
      const c = string.charCodeAt(n);
      if (c < 128) {
        utftext += String.fromCharCode(c);
      } else if (c > 127 && c < 2048) {
        utftext += String.fromCharCode((c >> 6) | 192);
        utftext += String.fromCharCode((c & 63) | 128);
      } else {
        utftext += String.fromCharCode((c >> 12) | 224);
        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
        utftext += String.fromCharCode((c & 63) | 128);
      }
    }
    return utftext;
  }

  private utf8Encode(utftext: string): string {
    let string = '';
    let i = 0;
    let c = 0;
    let c1 = 0;
    let c2 = 0;
    while (i < utftext.length) {
      c = utftext.charCodeAt(i);
      if (c < 128) {
        string += String.fromCharCode(c);
        i++;
      } else if (c > 191 && c < 224) {
        c1 = utftext.charCodeAt(i + 1);
        string += String.fromCharCode(((c & 31) << 6) | (c1 & 63));
        i += 2;
      } else {
        c1 = utftext.charCodeAt(i + 1);
        c2 = utftext.charCodeAt(i + 2);
        string += String.fromCharCode(
          ((c & 15) << 12) | ((c1 & 63) << 6) | (c2 & 63),
        );
        i += 3;
      }
    }
    return string;
  }

  private safeJsonEncode(obj) {
    return JSON.stringify(obj, null, 2).replace(
      /[\u007F-\uFFFF]/g,
      function (char) {
        return '\\u' + ('0000' + char.charCodeAt(0).toString(16)).substr(-4);
      },
    );
  }

  private trimZeros(input: string): string {
    return input.replace(/\0+$/g, '');
  }
}
