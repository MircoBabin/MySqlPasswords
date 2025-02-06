<?php
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

namespace MySqlServer;

class MySqlCredentials
{
    public const PasswordType_Empty = 10;
    public const PasswordType_Sensitive = 11;
    public const PasswordType_NotSensitive = 12;

    public const MySqlPluginType_default_with_password_in_plaintext = 20;
    public const MySqlPluginType_mysql_native_password = 21;
    public const MySqlPluginType_caching_sha2_password = 22;

    public $username;
    public $host;
    public $password;
    public $passwordtype;

    public $sslCaCertFilename;
    public $sslClientCertFilename;
    public $sslClientKeyFilename;

    public function __construct($username, $password, $passwordtype)
    {
        $this->username = $username;
        $this->host = '%';
        $this->password = $password;

        switch ($passwordtype) {
            case self::PasswordType_Empty:
            case self::PasswordType_Sensitive:
            case self::PasswordType_NotSensitive:
                $this->passwordtype = $passwordtype;
                break;

            default:
                throw new \Exception('Invalid passwordtype: '.$passwordtype);
        }

        $this->sslCaCertFilename = null;
        $this->sslClientCertFilename = null;
        $this->sslClientKeyFilename = null;
    }

    public function GetSqlForDropUser($AddIfExists)
    {
        $sql = '';

        $sql .= 'DROP USER ';
        if ($AddIfExists) {
            $sql .= 'IF EXISTS ';
        }
        $sql .= $this->GetSqlForUsernameAtHost();
        $sql .= ';';

        return $sql;
    }

    public function GetSqlForCreateUser($AddIfNotExists, $passwordPluginType, $usingSalt = null)
    {
        $sql = '';

        $sql .= 'CREATE USER ';
        if ($AddIfNotExists) {
            $sql .= 'IF NOT EXISTS ';
        }
        $sql .= $this->GetSqlForUsernameAtHost();
        $sql .= ' ';
        $sql .= $this->GetSqlForIdentifiedWithAs($passwordPluginType, $usingSalt);
        $sql .= ';';

        return $sql;
    }

    public function GetSqlForAlterUserPassword($AddIfExists, $passwordPluginType, $usingSalt = null)
    {
        $sql = '';

        $sql .= 'ALTER USER ';
        if ($AddIfExists) {
            $sql .= 'IF EXISTS ';
        }
        $sql .= $this->GetSqlForUsernameAtHost();
        $sql .= ' ';
        $sql .= $this->GetSqlForIdentifiedWithAs($passwordPluginType, $usingSalt);
        $sql .= ';';

        return $sql;
    }

    public function GetSqlForUsernameAtHost()
    {
        $sql = '';

        $sql .= $this->GetSqlForStringLiteral($this->username);
        $sql .= '@';
        $sql .= $this->GetSqlForStringLiteral($this->host);

        return $sql;
    }

    public function GetSqlForIdentifiedWithAs($passwordPluginType, $usingSalt = null)
    {
        $sql = '';

        switch ($passwordPluginType) {
            case self::MySqlPluginType_default_with_password_in_plaintext:
                $sql .= 'IDENTIFIED BY ';
                $sql .= $this->GetSqlForStringLiteral($this->password);
                break;

            case self::MySqlPluginType_mysql_native_password:
                $sql .= 'IDENTIFIED WITH mysql_native_password AS ';
                $sql .= $this->AsMysqlNativePassword();
                break;

            case self::MySqlPluginType_caching_sha2_password:
                $sql .= 'IDENTIFIED WITH caching_sha2_password AS ';
                $sql .= $this->AsCachingSha2Password($usingSalt);
                break;

            default:
                throw new \Exception('Unknown PluginType: '.$passwordPluginType);
        }

        return $sql;
    }

    public function GetSqlForStringLiteral($value)
    {
        if (null === $value) {
            return '\'\'';
        }

        if (!is_string($value)) {
            throw new \Exception('Value is not a string.');
        }

        // prevent sql injection - https://dev.mysql.com/doc/refman/8.4/en/string-literals.html
        $result = '';

        $result .= '\'';

        for ($i = 0; $i < strlen($value); ++$i) {
            $ch = substr($value, $i, 1);
            switch ($ch) {
                case "\x00":
                    $result .= '\\0';
                    break;

                case "'":
                    $result .= '\\\'';
                    break;

                case "\x08":
                    $result .= '\\b';
                    break;

                case "\n":
                    $result .= '\\n';
                    break;

                case "\r":
                    $result .= '\\r';
                    break;

                case "\t":
                    $result .= '\\t';
                    break;

                case "\x1a": // ctrl-z EOF
                    $result .= '\\Z';
                    break;

                case '\\':
                    $result .= '\\\\';
                    break;

                default:
                    $result .= $ch;
                    break;
            }
        }

        $result .= '\'';

        return $result;
    }

    public function AsMysqlNativePassword()
    {
        $passwordBytes = $this->ComputeStringToUtf8WithoutBom($this->password);
        $hashBytes = $this->ComputeSha1($this->ComputeSha1($passwordBytes));

        return $this->GetSqlForStringLiteral('*'.$this->ComputeBytesToUpperCaseHex($hashBytes));
    }

    private const AUTHENTICATION_STRING_DELIMITER = 0x24; // $

    public function GenerateSaltForCachingSha2Password($usingSalt = null)
    {
        $SALT_LENGTH = 20;

        if (null === $usingSalt) {
            return $this->randomAsciiSalt($SALT_LENGTH);
        }

        if (!is_string($usingSalt)) {
            throw new \Exception('usingSalt is not a binary/string.');
        }

        if (strlen($usingSalt) != $SALT_LENGTH) {
            throw new \Exception('usingSalt must be '.$SALT_LENGTH.' bytes, but is '.strlen($usingSalt).' bytes.');
        }

        for ($i = 0; $i < strlen($usingSalt); ++$i) {
            $b = ord(substr($usingSalt, $i, 1));

            if ($b < 0x20 || $b > 0x7E) {
                throw new \Exception('usingSalt must be in ASCII range [0x20 .. 0x7e], but contains 0x'.strtolower(bin2hex($b)));
            }

            if (self::AUTHENTICATION_STRING_DELIMITER == $b) {
                throw new \Exception('usingSalt must not contain DELIMITER 0x24 ($).');
            }

            if (0x27 == $b) {
                throw new \Exception('usingSalt must not contain QUOTE 0x27 (\').');
            }

            if (0x5C == $b) {
                throw new \Exception('usingSalt must not contain BACKSLASH 0x5c (\\).');
            }
        }

        return $usingSalt;
    }

    public function AsCachingSha2Password($usingSalt = null)
    {
        // https://crypto.stackexchange.com/questions/77427/whats-the-algorithm-behind-mysqls-sha256-password-hashing-scheme
        // select user,host,convert(authentication_string using binary),plugin from mysql.user;

        $ITERATION_MULTIPLIER = 1000;
        // $MAX_ITERATIONS = 100000;

        $STORED_SHA256_DIGEST_LENGTH = 43;

        $iterations = 5; // actually: iterations * ITERATION_MULTIPLIER

        $saltBytes = $this->GenerateSaltForCachingSha2Password($usingSalt);

        $passwordBytes = $this->ComputeStringToUtf8WithoutBom($this->password);

        $hashBits = 256; // SHA256 output bits
        $hashBytes = $hashBits / 8; // 32

        //
        // Step 1 - digest_b
        //
        $tmpBytes = $passwordBytes.$saltBytes.$passwordBytes;
        $digest_b = $this->ComputeSha256($tmpBytes);

        //
        // Step 2 - digest_a
        //
        $tmpBytes = $passwordBytes.$saltBytes;

        // Add for any character in the key one byte of the alternate sum.
        for ($i = strlen($passwordBytes); $i > 0; $i -= $hashBytes) {
            if ($i > $hashBytes) {
                $tmpBytes .= $digest_b;
            } else {
                $tmpBytes .= substr($digest_b, 0, $i);
            }
        }

        // Take the binary representation of the length of the key and for every 1 add the alternate sum, for every 0 the key.
        for ($i = strlen($passwordBytes); $i > 0; $i = intdiv($i, 2)) {
            if (($i & 1) != 0) {
                $tmpBytes .= $digest_b;
            } else {
                $tmpBytes .= $passwordBytes;
            }
        }

        $digest_a = $this->ComputeSha256($tmpBytes);

        //
        // Step 3 - digest_dp
        //

        // For every character in the password add the entire password.
        $tmpBytes = '';
        for ($i = 0; $i < strlen($passwordBytes); ++$i) {
            $tmpBytes .= $passwordBytes;
        }

        $digest_dp = $this->ComputeSha256($tmpBytes);

        //
        // Step 4 - sequence_p
        //
        $sequence_p = '';
        for ($i = strlen($passwordBytes); $i > 0; $i -= $hashBytes) {
            if ($i > $hashBytes) {
                $sequence_p .= $digest_dp;
            } else {
                $sequence_p .= substr($digest_dp, 0, $i);
            }
        }

        //
        // Step 5 - digest_ds
        //
        $tmpBytes = '';
        $til = 16 + ord($digest_a[0]);
        for ($i = 0; $i < $til; ++$i) {
            $tmpBytes .= $saltBytes;
        }

        $digest_ds = $this->ComputeSha256($tmpBytes);

        //
        // Step 6 - sequence_s
        //
        $sequence_s = '';
        for ($i = strlen($saltBytes); $i > 0; $i -= $hashBytes) {
            if ($i > $hashBytes) {
                $sequence_s .= $digest_ds;
            } else {
                $sequence_s .= substr($digest_ds, 0, $i);
            }
        }

        //
        // Step 7 - now we do iterations into digest_c
        //
        $digest_c = $digest_a;
        for ($i = 0; $i < ($iterations * $ITERATION_MULTIPLIER); ++$i) {
            if (($i & 1) != 0) {
                $tmpBytes = $sequence_p;
            } else {
                $tmpBytes = $digest_c;
            }

            if (($i % 3) != 0) {
                $tmpBytes .= $sequence_s;
            }
            if (($i % 7) != 0) {
                $tmpBytes .= $sequence_p;
            }

            if (($i & 1) != 0) {
                $tmpBytes .= $digest_c;
            } else {
                $tmpBytes .= $sequence_p;
            }

            $digest_c = $this->ComputeSha256($tmpBytes);
        }

        //
        // Step 8 - b64_result
        //

        // (hashBits == 256) SHA256 - define inc1, inc2, mod, end
        $inc1 = 10;
        $inc2 = 21;
        $mod = 30;
        $end = 0;

        $b64_result = '';

        $i = 0;
        do {
            $b64_result .= $this->B64Encode(
                (ord(substr($digest_c, $i, 1)) << 16) | (ord(substr($digest_c, ($i + $inc1) % $mod, 1)) << 8) | (ord(substr($digest_c, ($i + ($inc1 * 2)) % $mod, 1))), 4);
            $i = ($i + $inc2) % $mod;
        } while ($i != $end);

        // (hashBits == 256) SHA256
        $b64_result .= $this->B64Encode(
            (ord(substr($digest_c, 31, 1)) << 8) | (ord(substr($digest_c, 30, 1))), 3);

        if (strlen($b64_result) != $STORED_SHA256_DIGEST_LENGTH) {
            throw new \Exception('AsCachingSha2Password - b64_result must be '.$STORED_SHA256_DIGEST_LENGTH.' bytes, but is '.strlen($b64_result).'.');
        }

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

        $tmpBytes =
            chr(self::AUTHENTICATION_STRING_DELIMITER). // $
            chr(0x41). // A
            chr(self::AUTHENTICATION_STRING_DELIMITER). // $
            chr(0x30 + (intdiv($iterations, 100) % 10)). // 0
            chr(0x30 + (intdiv($iterations, 10) % 10)).  // 0
            chr(0x30 + (($iterations) % 10)).           // 5
            chr(self::AUTHENTICATION_STRING_DELIMITER). // $
            $saltBytes.$b64_result;

        // return 0xAA... uppercase hex string
        return '0x'.$this->ComputeBytesToUpperCaseHex($tmpBytes);
    }

    private function randomAsciiSalt($length)
    {
        static $_randomAsciiSalt_AllowedBytes =
        [
            // SALT bytes in ASCII range (and therefore also UTF-8) 0x20 - 0x7E with the exception of:
            // - DELIMITER $ (0x24)
            // - QUOTE ' (0x27) to prevent escaping problems.
            // - BACKSLASH \ (0x5c) to prevent escaping problems.
            // 92 bytes
            0x20, 0x21, 0x22, 0x23, /* $ */ 0x25, 0x26, /* ' */ 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, /* \ */ 0x5D, 0x5E, 0x5F,
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        ];

        //   0 ..  91
        //  92 .. 183
        // 184 .. 275 !!! bias, because the random range is 0..255 (a byte). The values 256..275 don't have a chance to get choosen.
        $maxUnbiased = 183;

        $result = '';

        $_randomPool = '';
        $_randomPoolIdx = 0;

        $idx = 0;
        while ($idx < $length) {
            if ($_randomPoolIdx >= strlen($_randomPool)) {
                $_randomPool = $this->ComputeSecureRandomBytes($length);
                $_randomPoolIdx = 0;
            }
            $_random = ord(substr($_randomPool, $_randomPoolIdx, 1));
            $_randomPoolIdx++;
            
            if ($_random <= $maxUnbiased) {
                $result .= chr($_randomAsciiSalt_AllowedBytes[$_random % count($_randomAsciiSalt_AllowedBytes)]);
                ++$idx;
            }
        }

        return $result;
    }

    private function B64Encode($valueToConvertToB64, $n)
    {
        static $_B64Encode_Table =
        [
            // ('.', '/', '0' ..'9', 'A' .. 'Z', 'a' .. 'z')
            0x2E, 0x2F,

            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,

            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,

            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
        ];

        // returns bytes in ASCII range (and therefore also UTF-8)
        $encoded = '';
        for ($i = 0; $i < $n; ++$i) {
            $encoded .= chr($_B64Encode_Table[$valueToConvertToB64 & 0x3F]);
            $valueToConvertToB64 >>= 6;
        }

        return $encoded;
    }
    
    private function ComputeBytesToUpperCaseHex($valueBytes)
    {
        return strtoupper(bin2hex($valueBytes));
    }
    
    private function ComputeStringToUtf8WithoutBom($value)
    {
        // A "string" in Php is actually an array of bytes.
        return strval($value);
    }
    
    private function ComputeSha1($valueBytes)
    {
        return hash('sha1', $valueBytes, true);
    }
    
    private function ComputeSha256($valueBytes)
    {
        return hash('sha256', $valueBytes, true);
    }
    
    private function ComputeSecureRandomBytes($length)
    {
        return random_bytes($length);
    }
}
