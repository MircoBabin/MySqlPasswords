/*
MySqlPasswords
https://github.com/MircoBabin/MySqlPasswords - MIT license 

Copyright (c) 2025 Mirco Babin

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace MySqlServer
{
    public class MySqlCredentials
    {
        public enum PasswordType
        {
            Empty,
            Sensitive,
            NotSensitive
        }

        public enum MySqlPluginType
        {
            default_with_password_in_plaintext,
            mysql_native_password,
            caching_sha2_password,
        }

        public string username { get; set; }
        public string host { get; set; }
        public SecureString password { get; set; }
        public PasswordType passwordtype { get; set; }

        public string sslCaCertFilename { get; set; }
        public string sslClientCertFilename { get; set; }
        public string sslClientKeyFilename { get; set; }

        public MySqlCredentials(string username, string password, PasswordType passwordtype)
        {
            SecureString securePassword = new SecureString();
            if (!string.IsNullOrEmpty(password))
            {
                foreach (var ch in password)
                {
                    securePassword.AppendChar(ch);
                }
            }

            Construct(username, securePassword, passwordtype);
        }

        public MySqlCredentials(string username, SecureString password, PasswordType passwordtype)
        {
            if (password == null)
                password = new SecureString();

            Construct(username, password, passwordtype);
        }

        public string GetSqlForDropUser(bool AddIfExists)
        {
            StringBuilder sql = new StringBuilder();

            sql.Append("DROP USER ");
            if (AddIfExists)
                sql.Append("IF EXISTS ");
            sql.Append(GetSqlForUsernameAtHost());
            sql.Append(";");

            return sql.ToString();
        }

        public string GetSqlForCreateUser(bool AddIfNotExists, MySqlPluginType passwordPluginType, byte[] usingSalt = null)
        {
            StringBuilder sql = new StringBuilder();

            sql.Append("CREATE USER ");
            if (AddIfNotExists)
                sql.Append("IF NOT EXISTS ");
            sql.Append(GetSqlForUsernameAtHost());
            sql.Append(" ");
            sql.Append(GetSqlForIdentifiedWithAs(passwordPluginType, usingSalt));
            sql.Append(";");

            return sql.ToString();
        }

        public string GetSqlForAlterUserPassword(bool AddIfExists, MySqlPluginType passwordPluginType, byte[] usingSalt = null)
        {
            StringBuilder sql = new StringBuilder();

            sql.Append("ALTER USER ");
            if (AddIfExists)
                sql.Append("IF EXISTS ");
            sql.Append(GetSqlForUsernameAtHost());
            sql.Append(" ");
            sql.Append(GetSqlForIdentifiedWithAs(passwordPluginType, usingSalt));
            sql.Append(";");

            return sql.ToString();
        }

        public string GetSqlForUsernameAtHost()
        {
            StringBuilder sql = new StringBuilder();

            sql.Append(GetSqlForUsername());
            sql.Append("@");
            sql.Append(GetSqlForHost());

            return sql.ToString();
        }

        public string GetSqlForUsername()
        {
            return GetSqlForStringLiteral(username);
        }

        public string GetSqlForHost()
        {
           return GetSqlForStringLiteral(host);
        }

        public string GetSqlForIdentifiedWithAs(MySqlPluginType passwordPluginType, byte[] usingSalt = null)
        {
            StringBuilder sql = new StringBuilder();

            switch (passwordPluginType)
            {
                case MySqlPluginType.default_with_password_in_plaintext:
                    sql.Append("IDENTIFIED BY ");
                    sql.Append(GetSqlForStringLiteral(getPasswordAsString()));
                    break;

                case MySqlPluginType.mysql_native_password:
                    sql.Append("IDENTIFIED WITH mysql_native_password AS ");
                    sql.Append(AsMysqlNativePassword());
                    break;

                case MySqlPluginType.caching_sha2_password:
                    sql.Append("IDENTIFIED WITH caching_sha2_password AS ");
                    sql.Append(AsCachingSha2Password(usingSalt));
                    break;

                default:
                    throw new Exception("Unknown PluginType: " + passwordPluginType.ToString());
            }

            return sql.ToString();
        }

        public string GetSqlForStringLiteral(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "''";

            // prevent sql injection - https://dev.mysql.com/doc/refman/8.4/en/string-literals.html
            StringBuilder result = new StringBuilder();

            result.Append("'");

            foreach (var ch in value)
            {
                switch (ch)
                {
                    case '\0':
                        result.Append("\\0");
                        break;

                    case '\'':
                        result.Append("\\'");
                        break;

                    case '\b':
                        result.Append("\\b");
                        break;

                    case '\n':
                        result.Append("\\n");
                        break;

                    case '\r':
                        result.Append("\\r");
                        break;

                    case '\t':
                        result.Append("\\t");
                        break;

                    case (char)0x1a: // ctrl-z EOF
                        result.Append("\\Z");
                        break;

                    case '\\':
                        result.Append("\\\\");
                        break;

                    default:
                        result.Append(ch);
                        break;
                }
            }

            result.Append("'");

            return result.ToString();
        }

        public string AsMysqlNativePassword()
        {
            var sha1 = SHA1.Create();

            byte[] passwordBytes = ComputeStringToUtf8WithoutBom(getPasswordAsString());
            byte[] hashBytes = ComputeSha1(ComputeSha1(passwordBytes));

            return GetSqlForStringLiteral("*" + ComputeBytesToUpperCaseHex(hashBytes));
        }

        private const byte AUTHENTICATION_STRING_DELIMITER = 0x24; // $

        public byte[] GenerateSaltForCachingSha2Password(string usingSalt = null)
        {
            if (string.IsNullOrEmpty(usingSalt))
                return GenerateSaltForCachingSha2Password((byte[])null);

            byte[] saltBytes = ComputeStringToUtf8WithoutBom(usingSalt);

            return GenerateSaltForCachingSha2Password(saltBytes);
        }

        public byte[] GenerateSaltForCachingSha2Password(byte[] usingSalt = null)
        {
            const int SALT_LENGTH = 20;

            if (usingSalt == null)
                return randomAsciiSalt(SALT_LENGTH);


            if (usingSalt.Length != SALT_LENGTH)
                throw new Exception("usingSalt must be " + SALT_LENGTH + " bytes, but is " + usingSalt.Length + " bytes.");

            foreach (byte b in usingSalt)
            {
                if (b < 0x20 || b > 0x7e)
                    throw new Exception("usingSalt must be in ASCII range [0x20 .. 0x7e], but contains 0x" + BitConverter.ToString(new byte[] { b }).Replace("-", "").ToLowerInvariant());

                if (b == AUTHENTICATION_STRING_DELIMITER)
                    throw new Exception("usingSalt must not contain DELIMITER 0x24 ($).");

                if (b == 0x27)
                    throw new Exception("usingSalt must not contain QUOTE 0x27 (').");

                if (b == 0x5c)
                    throw new Exception("usingSalt must not contain BACKSLASH 0x5c (\\).");
            }

            return usingSalt;
        }

        public string AsCachingSha2Password(byte[] usingSalt = null)
        {
            // https://crypto.stackexchange.com/questions/77427/whats-the-algorithm-behind-mysqls-sha256-password-hashing-scheme
            // select user,host,convert(authentication_string using binary),plugin from mysql.user;

            const int ITERATION_MULTIPLIER = 1000;
            //const int MAX_ITERATIONS = 100000;

            const int STORED_SHA256_DIGEST_LENGTH = 43;

            const byte iterations = 5; // actually: iterations * ITERATION_MULTIPLIER

            byte[] saltBytes = GenerateSaltForCachingSha2Password(usingSalt);

            byte[] passwordBytes = ComputeStringToUtf8WithoutBom(getPasswordAsString());

            const int hashBits = 256; // SHA256 output bits
            const int hashBytes = hashBits / 8; // 32
            byte[] tmpBytes;

            //
            // Step 1 - digest_b
            //
            tmpBytes = concatBytes(passwordBytes, saltBytes, passwordBytes);
            byte[] digest_b = ComputeSha256(tmpBytes);

            //
            // Step 2 - digest_a
            //
            tmpBytes = concatBytes(passwordBytes, saltBytes);

            // Add for any character in the key one byte of the alternate sum.
            for (var i = passwordBytes.Length; i > 0; i -= hashBytes)
            {
                if (i > hashBytes)
                    tmpBytes = concatBytes(tmpBytes, digest_b);
                else
                    tmpBytes = concatBytes(tmpBytes, sliceBytes(digest_b, 0, i));
            }

            // Take the binary representation of the length of the key and for every 1 add the alternate sum, for every 0 the key.
            for (var i = passwordBytes.Length; i > 0; i /= 2)
            {
                if ((i & 1) != 0)
                    tmpBytes = concatBytes(tmpBytes, digest_b);
                else
                    tmpBytes = concatBytes(tmpBytes, passwordBytes);
            }

            byte[] digest_a = ComputeSha256(tmpBytes);

            //
            // Step 3 - digest_dp
            //

            // For every character in the password add the entire password.
            tmpBytes = new byte[0];
            for (var i = 0; i < passwordBytes.Length; i++)
            {
                tmpBytes = concatBytes(tmpBytes, passwordBytes);
            }

            byte[] digest_dp = ComputeSha256(tmpBytes);

            //
            // Step 4 - sequence_p
            //
            byte[] sequence_p = new byte[0];
            for (var i = passwordBytes.Length; i > 0; i -= hashBytes)
            {
                if (i > hashBytes)
                    sequence_p = concatBytes(sequence_p, digest_dp);
                else
                    sequence_p = concatBytes(sequence_p, sliceBytes(digest_dp, 0, i));
            }

            //
            // Step 5 - digest_ds
            //
            tmpBytes = new byte[0];
            var til = 16 + digest_a[0];
            for (var i = 0; i < til; i++)
            {
                tmpBytes = concatBytes(tmpBytes, saltBytes);
            }

            byte[] digest_ds = ComputeSha256(tmpBytes);

            //
            // Step 6 - sequence_s
            //
            byte[] sequence_s = new byte[0];
            for (var i = saltBytes.Length; i > 0; i -= hashBytes)
            {
                if (i > hashBytes)
                    sequence_s = concatBytes(sequence_s, digest_ds);
                else
                    sequence_s = concatBytes(sequence_s, sliceBytes(digest_ds, 0, i));
            }

            //
            // Step 7 - now we do iterations into digest_c
            //
            byte[] digest_c = concatBytes(digest_a, new byte[0]);
            for (var i = 0; i < (iterations * ITERATION_MULTIPLIER); i++)
            {
                if ((i & 1) != 0)
                    tmpBytes = concatBytes(sequence_p, new byte[0]);
                else
                    tmpBytes = concatBytes(digest_c, new byte[0]);

                if ((i % 3) != 0) tmpBytes = concatBytes(tmpBytes, sequence_s);
                if ((i % 7) != 0) tmpBytes = concatBytes(tmpBytes, sequence_p);

                if ((i & 1) != 0)
                    tmpBytes = concatBytes(tmpBytes, digest_c);
                else
                    tmpBytes = concatBytes(tmpBytes, sequence_p);

                digest_c = ComputeSha256(tmpBytes);
            }

            //
            // Step 8 - b64_result
            //

            // (hashBits == 256) SHA256 - define inc1, inc2, mod, end
            const int inc1 = 10;
            const int inc2 = 21;
            const int mod = 30;
            const int end = 0;

            byte[] b64_result = new byte[0];
            {
                int i = 0;
                do
                {
                    b64_result = concatB64Encode(b64_result,
                        (digest_c[i] << 16) | (digest_c[(i + inc1) % mod] << 8) | (digest_c[(i + (inc1 * 2)) % mod]), 4);
                    i = (i + inc2) % mod;
                } while (i != end);
            }

            // (hashBits == 256) SHA256
            b64_result = concatB64Encode(b64_result,
                (digest_c[31] << 8) | (digest_c[30]), 3);

            if (b64_result.Length != STORED_SHA256_DIGEST_LENGTH)
                throw new Exception("AsCachingSha2Password - b64_result must be " + STORED_SHA256_DIGEST_LENGTH + " bytes, but is " + b64_result.Length + ".");

            //
            // Step 9 - table "mysql.user", field "authentication_string" output
            //

            /*
                https://github.com/mysql/mysql-server/blob/ea7d2e2d16ac03afdd9cb72a972a95981107bf51/sql/auth/sha2_password.cc#L404

                From stored string, following parts are retrieved:
                Digest type
                Salt
                Iteration count
                hash

                Expected format
                DELIMITER[digest_type]DELIMITER[iterations]DELIMITER[salt][digest]

                digest_type:
                A => SHA256

                iterations:
                005 => 5*ITERATION_MULTIPLIER

                salt:
                Random string. Length SALT_LENGTH

                digest:
                SHA2 digest. Length STORED_SHA256_DIGEST_LENGTH
            */

            tmpBytes = new byte[7];
            tmpBytes[0] = AUTHENTICATION_STRING_DELIMITER; // $
            tmpBytes[1] = 0x41;      // A
            tmpBytes[2] = AUTHENTICATION_STRING_DELIMITER; // $
            tmpBytes[3] = (byte)(0x30 + ((iterations / 100) % 10)); // 0
            tmpBytes[4] = (byte)(0x30 + ((iterations / 10) % 10));  // 0
            tmpBytes[5] = (byte)(0x30 + ((iterations) % 10));       // 5
            tmpBytes[6] = AUTHENTICATION_STRING_DELIMITER; // $
            tmpBytes = concatBytes(tmpBytes, saltBytes, b64_result);

            //return 0xAA... uppercase hex string
            return "0x" + ComputeBytesToUpperCaseHex(tmpBytes);
        }

        private static readonly byte[] _randomAsciiSalt_AllowedBytes = new byte[]
        {
            // SALT bytes in ASCII range (and therefore also UTF-8) 0x20 - 0x7E with the exception of:
            // - DELIMITER $ (0x24)
            // - QUOTE ' (0x27) to prevent escaping problems.
            // - BACKSLASH \ (0x5c) to prevent escaping problems.
            // 92 bytes
            0x20, 0x21, 0x22, 0x23, /*$*/ 0x25, 0x26, /*'*/ 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, /*\*/ 0x5d, 0x5e, 0x5f,
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        };
        private byte[] randomAsciiSalt(uint length)
        {
            //   0 ..  91
            //  92 .. 183
            // 184 .. 275 !!! bias, because the random range is 0..255 (a byte). The values 256..275 don't have a chance to get choosen.
            const uint maxUnbiased = 183;

            byte[] result = new byte[length];

            byte[] _randomPool = new byte[0];
            uint _randomPoolIdx = 0;

            uint idx = 0;
            while (idx < length)
            {
                if (_randomPoolIdx >= _randomPool.Length)
                {
                    _randomPool = ComputeSecureRandomBytes(length);
                    _randomPoolIdx = 0;
                }
                byte _random = _randomPool[_randomPoolIdx];
                _randomPoolIdx++;

                if (_random <= maxUnbiased)
                {
                    result[idx] = _randomAsciiSalt_AllowedBytes[_random % _randomAsciiSalt_AllowedBytes.Length];
                    idx++;
                }
            }

            return result;
        }

        private static readonly byte[] _B64Encode_Table = new byte[]
        {
            // ('.', '/', '0' ..'9', 'A' .. 'Z', 'a' .. 'z')
            0x2e, 0x2f,

            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,

            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,

            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
        };
        private byte[] B64Encode(int valueToConvertToB64, int n)
        {
            // returns bytes in ASCII range (and therefore also UTF-8)
            var encoded = new byte[n];
            for (var i = 0; i < n; i++)
            {
                encoded[i] = _B64Encode_Table[valueToConvertToB64 & 0x3f];
                valueToConvertToB64 >>= 6;
            }

            return encoded;
        }

        private string ComputeBytesToUpperCaseHex(byte[] value)
        {
            return BitConverter.ToString(value).Replace("-", String.Empty).ToUpperInvariant();
        }

        private byte[] ComputeStringToUtf8WithoutBom(string value)
        {
            Encoding Utf8NoBom = new UTF8Encoding(false);

            return Utf8NoBom.GetBytes(value);
        }

        private byte[] ComputeSha1(byte[] value)
        {
            var sha1 = SHA1.Create();

            return sha1.ComputeHash(value);
        }

        private byte[] ComputeSha256(byte[] value)
        {
            var sha256 = SHA256.Create();

            return sha256.ComputeHash(value);
        }

        private byte[] ComputeSecureRandomBytes(uint Length)
        {
            var rng = new RNGCryptoServiceProvider();
            byte[] result = new byte[Length];
            rng.GetBytes(result);

            return result;
        }

        private byte[] sliceBytes(byte[] bytes, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(bytes, offset, result, 0, count);

            return result;
        }

        private byte[] concatBytes(byte[] bytes1, byte[] bytes2)
        {
            byte[] result = new byte[bytes1.Length + bytes2.Length];
            Buffer.BlockCopy(bytes1, 0, result, 0, bytes1.Length);
            Buffer.BlockCopy(bytes2, 0, result, bytes1.Length, bytes2.Length);

            return result;
        }

        private byte[] concatBytes(byte[] bytes1, byte[] bytes2, byte[] bytes3)
        {
            byte[] result = new byte[bytes1.Length + bytes2.Length + bytes3.Length];
            Buffer.BlockCopy(bytes1, 0, result, 0, bytes1.Length);
            Buffer.BlockCopy(bytes2, 0, result, bytes1.Length, bytes2.Length);
            Buffer.BlockCopy(bytes3, 0, result, bytes1.Length + bytes2.Length, bytes3.Length);

            return result;
        }

        private byte[] concatB64Encode(byte[] bytes, int valueToConvertToB64, int n)
        {
            return concatBytes(bytes, B64Encode(valueToConvertToB64, n));
        }

        private void Construct(string username, SecureString password, PasswordType passwordtype)
        {
            this.username = username;
            this.host = "%";
            this.password = password;
            this.passwordtype = passwordtype;

            this.sslCaCertFilename = null;
            this.sslClientCertFilename = null;
            this.sslClientKeyFilename = null;
        }

        private string getPasswordAsString()
        {
            IntPtr valuePtr = IntPtr.Zero;

            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(password);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }
    }
}
