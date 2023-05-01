import * as crypto from 'crypto';
import { Injectable } from '@nestjs/common';

@Injectable()
export class RsaService {
  private publicKey: { e: bigint; n: bigint };
  private privateKey: { d: bigint; n: bigint };
  constructor() {
    const { privateKey, publicKey } = this.generateKeys();
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public encrypt(message: string): string {
    const { e, n } = this.publicKey;
    const m = BigInt('0x' + Buffer.from(message).toString('hex'));
    const c = this.modPow(m, e, n); //  m^e % n
    return c.toString(16);
  }

  public decrypt(ciphertext: string): string {
    const { d, n } = this.privateKey;
    const c = BigInt('0x' + ciphertext);
    const m = this.modPow(c, d, n); // c^d % n
    const message = Buffer.from(m.toString(16), 'hex').toString();
    return message;
  }

  private gcd(a: bigint, b: bigint): bigint {
    if (b === 0n) return a;
    return this.gcd(b, a % b);
  }

  private modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) {
      return 0n;
    }
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      exponent = exponent >> 1n;
      base = (base * base) % modulus;
    }
    return result;
  }

  private modInverse(a: bigint, m: bigint): bigint {
    const [g, x] = this.extendedGCD(a, m);
    if (g !== 1n) {
      throw new Error("Inverse doesn't exist");
    }
    return ((x % m) + m) % m;
  }

  private extendedGCD(a: bigint, b: bigint) {
    if (b === 0n) return [a, 1n, 0n];
    const [g, x, y] = this.extendedGCD(b, a % b);
    return [g, y, x - (a / b) * y];
  }

  private generateKeys(bits = 1024) {
    const p = crypto.generatePrimeSync(bits, { bigint: true });
    const q = crypto.generatePrimeSync(bits, { bigint: true });
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    let e = 3n;
    while (this.gcd(e, phi) !== 1n) {
      e += 2n;
    }
    const d = this.modInverse(e, phi); // (e * d) % phi = 1
    return {
      publicKey: { e, n },
      privateKey: { d, n },
    };
  }
}
