const crypto = require('crypto');

function gcd(a, b) {
  if (b === 0n) return a;
  return gcd(b, a % b);
}

function modPow(base, exponent, modulus) {
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

function modInverse(a, m) {
  const [g, x, _] = extendedGCD(a, m);
  if (g !== 1n) {
    throw new Error("Inverse doesn't exist");
  }
  return (x % m + m) % m;
}

function extendedGCD(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x, y] = extendedGCD(b, a % b);
  return [g, y, x - a / b * y];
}

function generateKeys(bits = 1024) {
  const p = crypto.generatePrimeSync(bits, { bigint: true });
  const q = crypto.generatePrimeSync(bits, { bigint: true });
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  let e = 3n;
  while (gcd(e, phi) !== 1n) {
    e += 2n;
  }
  const d = modInverse(e, phi); // (e * d) % phi = 1
  return {
    publicKey: { e, n },
    privateKey: { d, n },
  };
}

function encrypt(message, publicKey) {
  const { e, n } = publicKey;
  const m = BigInt("0x" + Buffer.from(message).toString("hex"));
  const c = modPow(m, e, n); //  m^e % n
  return c.toString(16);
}

function decrypt(ciphertext, privateKey) {
  const { d, n } = privateKey;
  const c = BigInt("0x" + ciphertext);
  const m = modPow(c, d, n); // c^d % n
  const message = Buffer.from(m.toString(16), "hex").toString();
  return message;
}

// Example usage
const { publicKey, privateKey } = generateKeys();
const message = "Hello, world!";
const encrypted = encrypt(message, publicKey);
console.log("Encrypted message:", encrypted);
const decrypted = decrypt(encrypted, privateKey);
console.log("Decrypted message:", decrypted);
