using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SpicyAD
{
    /// <summary>
    /// AES (etype 17 / 18) Kerberos crypto per RFC 3961 (simplified profile) and RFC 3962.
    /// Provides string2key (password -> base key) and the encrypt operation used for
    /// PA-ENC-TIMESTAMP, so the password spray works against DCs where RC4 is disabled.
    ///
    /// This mirrors what the existing RC4 path already does; it is not new attack capability,
    /// just protocol parity for hardened domains.
    /// </summary>
    internal static class KerberosAES
    {
        public const int ETYPE_AES128 = 17;
        public const int ETYPE_AES256 = 18;

        // Key sizes in bytes
        private static int KeySize(int etype) => etype == ETYPE_AES256 ? 32 : 16;

        // RFC 3962: 4096 iterations is the default unless the DC advertises otherwise
        // via PA-ETYPE-INFO2. For a spray we use the default; a mismatch surfaces as
        // PREAUTH_FAILED which the caller already handles.
        private const int DefaultIterations = 4096;

        /// <summary>
        /// string2key: derive the AES base key from a password.
        /// salt = REALM + principal-without-realm (e.g. "EVILCORP.NETjdoe"), unless an
        /// explicit salt was provided by the DC.
        /// </summary>
        public static byte[] StringToKey(string password, string salt, int etype, int iterations = DefaultIterations)
        {
            int keyLen = KeySize(etype);

            byte[] passBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            // tkey = random2key(PBKDF2(password, salt, iter, keyLen))
            byte[] tkey = PBKDF2_HMAC_SHA1(passBytes, saltBytes, iterations, keyLen);

            // key = DK(tkey, "kerberos") -- derive with the well-known constant
            byte[] kerberosConstant = Encoding.ASCII.GetBytes("kerberos");
            return DK(tkey, kerberosConstant, etype);
        }

        /// <summary>
        /// Encrypt plaintext for the given key usage, producing the Kerberos
        /// ciphertext = AES-CTS(confounder|plaintext|pad) || HMAC-SHA1-96 truncated.
        /// Used for PA-ENC-TIMESTAMP (key usage 1).
        /// </summary>
        public static byte[] Encrypt(byte[] baseKey, byte[] plaintext, int keyUsage, int etype)
        {
            // Derive Ke (encryption) and Ki (integrity) from the base key.
            byte[] ke = DK(baseKey, UsageConstant(keyUsage, 0xAA), etype);
            byte[] ki = DK(baseKey, UsageConstant(keyUsage, 0x55), etype);

            // confounder is one cipher block (16 bytes for AES)
            byte[] confounder = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(confounder);

            byte[] toEnc = new byte[confounder.Length + plaintext.Length];
            Buffer.BlockCopy(confounder, 0, toEnc, 0, confounder.Length);
            Buffer.BlockCopy(plaintext, 0, toEnc, confounder.Length, plaintext.Length);

            byte[] cipher = AesCtsEncrypt(ke, toEnc);

            // HMAC-SHA1 over the same (confounder|plaintext), truncated to 96 bits (12 bytes)
            byte[] mac;
            using (var hmac = new HMACSHA1(ki))
                mac = hmac.ComputeHash(toEnc);

            byte[] checksum = new byte[12];
            Buffer.BlockCopy(mac, 0, checksum, 0, 12);

            byte[] result = new byte[cipher.Length + checksum.Length];
            Buffer.BlockCopy(cipher, 0, result, 0, cipher.Length);
            Buffer.BlockCopy(checksum, 0, result, cipher.Length, checksum.Length);
            return result;
        }

        // ----- RFC 3961 key derivation primitives -----

        // DK(key, constant) = random2key(DR(key, constant))
        // For AES, random2key is the identity, and DR produces keylength bytes.
        private static byte[] DK(byte[] key, byte[] constant, int etype)
        {
            int keyLen = KeySize(etype);
            return DR(key, constant, keyLen);
        }

        // DR(key, constant): n-fold the constant to one block, then CBC-encrypt repeatedly
        // feeding output back in until we have keyLen bytes.
        private static byte[] DR(byte[] key, byte[] constant, int keyLen)
        {
            int blockSize = 16; // AES block
            byte[] ki = NFold(constant, blockSize);

            List<byte> output = new List<byte>();
            byte[] block = ki;
            while (output.Count < keyLen)
            {
                block = AesEcbEncryptBlock(key, block); // CBC with zero IV over a single block == ECB of that block
                output.AddRange(block);
            }
            return output.GetRange(0, keyLen).ToArray();
        }

        // Key-usage constant: 4-byte big-endian usage, then a one-byte tag (0xAA enc, 0x55 integrity).
        private static byte[] UsageConstant(int keyUsage, byte tag)
        {
            return new byte[]
            {
                (byte)((keyUsage >> 24) & 0xFF),
                (byte)((keyUsage >> 16) & 0xFF),
                (byte)((keyUsage >> 8) & 0xFF),
                (byte)(keyUsage & 0xFF),
                tag
            };
        }

        // ----- n-fold (RFC 3961 section 5.1) -----
        private static byte[] NFold(byte[] input, int outBytes)
        {
            int inBits = input.Length * 8;
            int outBits = outBytes * 8;
            int lcm = Lcm(inBits, outBits);
            int replicate = lcm / inBits;

            byte[] sumBytes = new byte[lcm / 8];

            // Build the rotated/replicated stream
            for (int i = 0; i < replicate; i++)
            {
                int rotation = 13 * i;
                byte[] rotated = RotateRight(input, rotation);
                Buffer.BlockCopy(rotated, 0, sumBytes, i * input.Length, input.Length);
            }

            // Now do the modular ones-complement addition in outBytes-sized chunks
            byte[] result = new byte[outBytes];
            int carry = 0;
            for (int i = outBytes - 1; i >= 0; i--)
            {
                int colSum = carry;
                for (int chunk = 0; chunk < (sumBytes.Length / outBytes); chunk++)
                {
                    colSum += sumBytes[chunk * outBytes + i];
                }
                result[i] = (byte)(colSum & 0xFF);
                carry = colSum >> 8;
            }
            // propagate the end-around carry
            if (carry > 0)
            {
                for (int i = outBytes - 1; i >= 0; i--)
                {
                    int v = result[i] + carry;
                    result[i] = (byte)(v & 0xFF);
                    carry = v >> 8;
                    if (carry == 0) break;
                }
            }
            return result;
        }

        // Rotate the bit string right by `bits` positions, returning a copy of input.Length bytes.
        private static byte[] RotateRight(byte[] input, int bits)
        {
            int n = input.Length;
            int totalBits = n * 8;
            bits %= totalBits;
            if (bits == 0) return (byte[])input.Clone();

            byte[] output = new byte[n];
            for (int i = 0; i < totalBits; i++)
            {
                int srcBit = (i - bits + totalBits) % totalBits;
                int srcByte = srcBit / 8;
                int srcOff = 7 - (srcBit % 8);
                int bit = (input[srcByte] >> srcOff) & 1;

                int dstByte = i / 8;
                int dstOff = 7 - (i % 8);
                if (bit != 0)
                    output[dstByte] |= (byte)(1 << dstOff);
            }
            return output;
        }

        private static int Gcd(int a, int b) { while (b != 0) { int t = b; b = a % b; a = t; } return a; }
        private static int Lcm(int a, int b) => a / Gcd(a, b) * b;

        // ----- AES primitives -----

        // Single-block AES encrypt with zero IV (used as the CBC step in DR).
        private static byte[] AesEcbEncryptBlock(byte[] key, byte[] block)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (var enc = aes.CreateEncryptor())
                {
                    byte[] outp = new byte[16];
                    enc.TransformBlock(block, 0, 16, outp, 0);
                    return outp;
                }
            }
        }

        // AES in CBC mode with ciphertext stealing (CTS), zero IV, per RFC 3962.
        private static byte[] AesCtsEncrypt(byte[] key, byte[] data)
        {
            const int bs = 16;
            if (data.Length == bs)
            {
                // Exactly one block: plain CBC (== ECB with zero IV)
                return AesCbcEncryptNoCts(key, data);
            }

            int n = (data.Length + bs - 1) / bs; // number of blocks (last may be partial)

            // CBC-encrypt all blocks normally (zero-pad the last partial block).
            byte[] padded = new byte[n * bs];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);

            byte[] cbc = AesCbcEncryptNoCts(key, padded);

            // Ciphertext stealing: swap the last two blocks and truncate the final
            // ciphertext block to the length of the last plaintext block.
            int lastLen = data.Length - (n - 1) * bs; // length of the final (possibly partial) block

            byte[] result = new byte[data.Length];
            // copy first n-2 blocks unchanged
            int firstBytes = (n - 2) * bs;
            if (firstBytes > 0)
                Buffer.BlockCopy(cbc, 0, result, 0, firstBytes);

            byte[] secondLast = new byte[bs];
            byte[] last = new byte[bs];
            Buffer.BlockCopy(cbc, (n - 2) * bs, secondLast, 0, bs);
            Buffer.BlockCopy(cbc, (n - 1) * bs, last, 0, bs);

            // result: ... | last (truncated to lastLen goes AFTER) ...
            // CTS output order: C_{n-1}* ... C_n becomes the truncated penultimate, swapped.
            // Place full 'last' block as the second-to-last block, then 'secondLast' truncated.
            Buffer.BlockCopy(last, 0, result, (n - 2) * bs, bs);
            Buffer.BlockCopy(secondLast, 0, result, (n - 1) * bs, lastLen);

            return result;
        }

        private static byte[] AesCbcEncryptNoCts(byte[] key, byte[] data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.IV = new byte[16];
                using (var enc = aes.CreateEncryptor())
                {
                    return enc.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // ----- PBKDF2-HMAC-SHA1 -----
        private static byte[] PBKDF2_HMAC_SHA1(byte[] password, byte[] salt, int iterations, int dkLen)
        {
            using (var derive = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                return derive.GetBytes(dkLen);
            }
        }
    }
}
