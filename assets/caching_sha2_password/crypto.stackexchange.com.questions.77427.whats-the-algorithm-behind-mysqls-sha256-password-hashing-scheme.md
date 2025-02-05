https://crypto.stackexchange.com/questions/77427/whats-the-algorithm-behind-mysqls-sha256-password-hashing-scheme

The algorithm implemented in hashcat works for me with mysql 8.0.

```php
<?php

// based on https://github.com/hashcat/hashcat/blob/master/tools/test_modules/m07400.pm

function to64($v, $n) {
    # ('.', '/', '0'..'9', 'A'..'Z', 'a'..'z');
    $i64 = array_merge(array('.', '/'), range('0', '9'), range('A', 'Z'), range('a', 'z'));

    $str = '';
    while (--$n >= 0) {
        $str .= $i64[$v & 0x3F];
        $v >>= 6;
    }
    return $str;
}

function sha256($data) {
    return hash("sha256", $data, true);
}

function sha_crypts($func, $bits, $key, $salt, $loops) {
    $bytes = $bits / 8;
    $b = $func($key . $salt . $key);

    # Add for any character in the key one byte of the alternate sum.

    $tmp = $key . $salt;

    for ($i = strlen($key); $i > 0; $i -= $bytes) {
        if ($i > $bytes) {
            $tmp .= $b;
        } else {
            $tmp .= substr ($b, 0, $i);
        }
    }

    # Take the binary representation of the length of the key and for every 1 add the alternate sum, for every 0 the key.

    for ($i = strlen($key); $i > 0; $i >>= 1) {
        if (($i & 1) != 0) {
            $tmp .= $b;
        } else {
            $tmp .= $key;
        }
    }

    $a = $func($tmp);

    # NOTE, this will be the 'initial' $c value in the inner loop.

    # For every character in the password add the entire password.  produces DP

    $tmp = "";

    for ($i = 0; $i < strlen($key); $i++) {
        $tmp .= $key;
    }

    $dp = $func($tmp);

    # Create byte sequence P

    $p = "";

    for ($i = strlen($key); $i > 0; $i -= $bytes) {
        if ($i > $bytes) {
            $p .= $dp;
        } else {
            $p .= substr ($dp, 0, $i);
        }
    }

    # produce ds

    $tmp = "";

    $til = 16 + ord (substr ($a, 0, 1));

    for ($i = 0; $i < $til; $i++) {
        $tmp .= $salt;
    }

    $ds = $func($tmp);

    # Create byte sequence S

    $s = "";

    for ($i = strlen($salt); $i > 0; $i -= $bytes) {
        if ($i > $bytes) {
            $s .= $ds;
        } else {
            $s .= substr ($ds, 0, $i);
        }
    }

    $c = $a; # Ok, we saved this, which will 'seed' our crypt value here in the loop.

    # now we do 5000 iterations of SHA2 (256 or 512)

    for ($i = 0; $i < $loops; $i++) {
        if ($i & 1) { $tmp  = $p; }
        else        { $tmp  = $c; }

        if ($i % 3) { $tmp .= $s; }
        if ($i % 7) { $tmp .= $p; }

        if ($i & 1) { $tmp .= $c; }
        else        { $tmp .= $p; }

        $c = $func($tmp);
    }

    #my $inc1; my $inc2; my $mod; my $end;

    if ($bits == 256) { $inc1 = 10; $inc2 = 21; $mod = 30; $end =  0; }
    else              { $inc1 = 21; $inc2 = 22; $mod = 63; $end = 21; }

    $i = 0;
    $tmp = "";

    do {
        $tmp .= to64 ((ord (substr ($c, $i, 1)) << 16) | (ord (substr ($c, ($i + $inc1) % $mod, 1)) << 8) | ord (substr ($c, ($i + $inc1 * 2) % $mod, 1)), 4);
        $i = ($i + $inc2) % $mod;
    } while ($i != $end);

    if ($bits == 256) { $tmp .= to64 ((ord (substr ($c, 31, 1)) << 8) | ord (substr ($c, 30, 1)), 3); }
    else              { $tmp .= to64  (ord (substr ($c, 63, 1)), 2); }

    return $tmp;
}

# pass - string
# salt - 20 bytes in utf8 compatible binary form
function mysql_caching_sha2_password($pass, $saltbin) {
    $count = 5;
    $iter = 1000 * $count;

    $dgst = sha_crypts("sha256", 256, $pass, $saltbin, $iter);

    $hash = sprintf ("\\\$A\\\$%03d\\\$%s%s", $count, $saltbin, $dgst);
    return $hash;
}

function gen_utf8_salt($len) {
    $r = '';
    for ($i = 0; $i < $len; $i++) {
        // Generate a random Unicode code point between U+0020 and U+007E
        $codePoint = mt_rand(0x0020, 0x007E);
        // Convert the code point to a UTF-8 string
        $r .= mb_convert_encoding('&#'.intval($codePoint).';', 'UTF-8', 'HTML-ENTITIES');
    }
    $r = str_replace('$', '%', $r);
    return $r;
}


$pass = "ąśóżźńÓĄŻŹŃ";
print("for password: $pass\n");
$saltbin = gen_utf8_salt(20);
$hash = mysql_caching_sha2_password($pass, $saltbin);
print("newbin: " . $hash . "\n");
print("newhex: " . strtoupper(current(unpack("H*", $hash))) . "\n");
```

Format used is:

```
$A$count$<salt><hash>
```

salt: 20 bytes binary (needs to be in utf-8 range)

hash: sha256 crypt of count\*1000 rounds of binary data and salt

Edit: salt can't contain '$'

answered Mar 21, 2024 at 18:26
arekm

(MircoBabin) Note: salt must be ASCII (0x20 upto 0x7e) and must not contain delimiter $, quote ' or backslash \\. Quote and backslash also to prevent sql injection.