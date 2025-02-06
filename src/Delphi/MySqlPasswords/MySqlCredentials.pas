{
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
}

unit MySqlCredentials;

interface
uses SysUtils;

type TMySqlCredentials = class
public
    type TPasswordType = (
        Empty,
        Sensitive,
        NotSensitive
    );

    type TMySqlPluginType = (
        default_with_password_in_plaintext,
        mysql_native_password,
        caching_sha2_password
    );

private
    Fusername : string;
    Fhost : string;
    Fpassword : string;
    Fpasswordtype : TPasswordType;

    FsslCaCertFilename : string;
    FsslClientCertFilename : string;
    FsslClientKeyFilename : string;

private
    const AUTHENTICATION_STRING_DELIMITER : byte = $24; // $

    function randomAsciiSalt(len : cardinal) : TBytes;
    function B64Encode(valueToConvertToB64 : integer; n : integer) : TBytes;

    function ComputeBytesToUpperCaseHex(value : TBytes) : string;
    function ComputeStringToUtf8WithoutBom(value : string) : TBytes;
    function ComputeSha1(value : TBytes) : TBytes;
    function ComputeSha256(value : TBytes) : TBytes;
    function ComputeSecureRandomBytes(len : cardinal) : TBytes;

    function sliceBytes(bytes : TBytes; offset : integer; count : integer) : TBytes;
    function concatBytes(bytes1 : TBytes; bytes2 : TBytes) : TBytes; overload;
    function concatBytes(bytes1 : TBytes; bytes2 : TBytes; bytes3 : TBytes) : TBytes; overload;
    function concatB64Encode(bytes : TBytes; valueToConvertToB64 : integer; n : integer) : TBytes;

public
    constructor Create(username : string; password : string; passwordtype : TPasswordType);
    
    function GetSqlForDropUser(AddIfExists : boolean) : string;
    function GetSqlForCreateUser(AddIfNotExists : boolean; passwordPluginType : TMySqlPluginType; usingSalt : TBytes = nil) : string;
    function GetSqlForAlterUserPassword(AddIfExists : boolean; passwordPluginType : TMySqlPluginType; usingSalt : TBytes = nil) : string;
    
    function GetSqlForUsernameAtHost() : string;
    function GetSqlForIdentifiedWithAs(passwordPluginType : TMySqlPluginType; usingSalt : TBytes = nil) : string;
    function GetSqlForStringLiteral(value : string) : string;
    
    function AsMysqlNativePassword() : string;
    function GenerateSaltForCachingSha2Password(usingSalt : string = '') : TBytes; overload;
    function GenerateSaltForCachingSha2Password(usingSalt : TBytes = nil) : TBytes; overload;
    function AsCachingSha2Password(usingSalt : TBytes = nil) : string;
    
    property username : string read Fusername write Fusername;
    property host : string read Fhost write Fhost;
    property password : string read Fpassword write Fpassword;
    property passwordtype : TPasswordType read Fpasswordtype write Fpasswordtype;
    
    property sslCaCertFilename : string read FsslCaCertFilename write FsslCaCertFilename;
    property sslClientCertFilename : string read FsslClientCertFilename write FsslClientCertFilename;
    property sslClientKeyFilename : string read FsslClientKeyFilename write FsslClientKeyFilename;
end;

implementation
uses System.Hash, System.TypInfo, Windows;

constructor TMySqlCredentials.Create(username : string; password : string; passwordtype : TPasswordType);
begin
    Fusername := username;
    Fhost := '%';
    Fpassword := password;
    Fpasswordtype := passwordtype;
    
    FsslCaCertFilename := '';
    FsslClientCertFilename := '';
    FsslClientKeyFilename := '';
end;

function TMySqlCredentials.GetSqlForDropUser(AddIfExists : boolean) : string;
var sql : string;
begin
    sql := '';
    sql := sql + 'DROP USER ';
    if (AddIfExists) then
        sql := sql + 'IF EXISTS ';
    sql := sql + GetSqlForUsernameAtHost();
    sql := sql + ';';

    Result := sql;    
end;
    
function TMySqlCredentials.GetSqlForCreateUser(AddIfNotExists : boolean; passwordPluginType : TMySqlPluginType; usingSalt : TBytes = nil) : string;
var sql : string;
begin
    sql := '';
    sql := sql + 'CREATE USER ';
    if (AddIfNotExists) then
        sql := sql + 'IF NOT EXISTS ';
    sql := sql + GetSqlForUsernameAtHost();
    sql := sql + ' ';
    sql := sql + GetSqlForIdentifiedWithAs(passwordPluginType, usingSalt);
    sql := sql + ';';

    Result := sql;    
end;

function TMySqlCredentials.GetSqlForAlterUserPassword(AddIfExists : boolean; passwordPluginType : TMySqlPluginType; usingSalt : TBytes = nil) : string;
var sql : string;
begin
    sql := '';
    sql := sql + 'ALTER USER ';
    if (AddIfExists) then
        sql := sql + 'IF EXISTS ';
    sql := sql + GetSqlForUsernameAtHost();
    sql := sql + ' ';
    sql := sql + GetSqlForIdentifiedWithAs(passwordPluginType, usingSalt);
    sql := sql + ';';

    Result := sql;    
end;

function TMySqlCredentials.GetSqlForUsernameAtHost() : string;
var sql : string;
begin
    sql := '';
    sql := sql + GetSqlForStringLiteral(Fusername);
    sql := sql + '@';
    sql := sql + GetSqlForStringLiteral(Fhost);

    Result := sql;    
end;

function TMySqlCredentials.GetSqlForIdentifiedWithAs(passwordPluginType : TMySqlPluginType; usingSalt : TBytes = nil) : string;
var sql : string;
begin
    sql := '';
    
    case passwordPluginType of
        TMySqlPluginType.default_with_password_in_plaintext:
            begin
                sql := sql + 'IDENTIFIED BY ';
                sql := sql + GetSqlForStringLiteral(Fpassword);
            end;

        TMySqlPluginType.mysql_native_password:
            begin
                sql := sql + 'IDENTIFIED WITH mysql_native_password AS ';
                sql := sql + AsMysqlNativePassword();
            end;

        TMySqlPluginType.caching_sha2_password:
            begin
                sql := sql + 'IDENTIFIED WITH caching_sha2_password AS ';
                sql := sql + AsCachingSha2Password(usingSalt);
            end;

        else
            begin
                raise Exception.Create('Unknown PluginType: ' + GetEnumName(TypeInfo(TMySqlPluginType), Integer(passwordPluginType)));
            end;
    end;
    
    Result := sql;    
end;

function TMySqlCredentials.GetSqlForStringLiteral(value : string) : string;
var i : integer;
    ch : char;
begin
    if (value = '') then
        begin
            Result := '''''';
            Exit;
        end;
        
    // prevent sql injection - https://dev.mysql.com/doc/refman/8.4/en/string-literals.html
    Result := '';

    Result := Result + '''';
    
    for i:=1 to Length(value) do
    begin
        ch := value[i];
        
        case ch of
            #0:
                begin
                    Result := Result + '\0';
                end;
                
            '''':
                begin
                    Result := Result + '\''';
                end;
                
            #8:
                begin
                    Result := Result + '\b';
                end;
                
            #10:
                begin
                    Result := Result + '\n';
                end;
                
            #13:
                begin
                    Result := Result + '\r';
                end;
                
            #9:
                begin
                    Result := Result + '\t';
                end;
                
            #26:  // ctrl-z EOF
                begin
                    Result := Result + '\Z';
                end;
                
            '\':
                begin
                    Result := Result + '\\';
                end;
                
            else
                begin
                    Result := Result + ch;
                end;
        end;
    end;
    
    Result := Result + '''';
end;

function TMySqlCredentials.AsMysqlNativePassword() : string;
var passwordBytes : TBytes;
    hashBytes : TBytes;
begin
    passwordBytes := ComputeStringToUtf8WithoutBom(Fpassword);
    hashBytes := ComputeSha1(ComputeSha1(passwordBytes));

    Result := GetSqlForStringLiteral('*' + ComputeBytesToUpperCaseHex(hashBytes));
end;

function TMySqlCredentials.GenerateSaltForCachingSha2Password(usingSalt : string = '') : TBytes;
var saltBytes : TBytes;
begin
    if (usingSalt = '') then
        begin
            Result := GenerateSaltForCachingSha2Password(TBytes(nil));
            Exit;
        end;

    saltBytes := ComputeStringToUtf8WithoutBom(usingSalt);

    Result := GenerateSaltForCachingSha2Password(saltBytes);
end;

function TMySqlCredentials.GenerateSaltForCachingSha2Password(usingSalt : TBytes = nil) : TBytes;
const SALT_LENGTH : integer = 20;
var i : integer;
    b : byte;
begin
    if ((usingSalt = nil) or (Length(usingSalt) = 0)) then
        begin
            Result := randomAsciiSalt(SALT_LENGTH);
            Exit;
        end;
        
    if (Length(usingSalt) <> SALT_LENGTH) then
        raise Exception.Create('usingSalt must be ' + IntToStr(SALT_LENGTH) + ' bytes, but is ' + IntToStr(Length(usingSalt)) + ' bytes.');
    
    for i:=Low(usingSalt) to High(usingSalt) do
    begin
        b := usingSalt[i];
        
        if ((b < $20) or (b > $7e)) then
            raise Exception.Create('usingSalt must be in ASCII range [0x20 .. 0x7e], but contains 0x' + LowerCase(IntToHex(b, 2)));

        if (b = AUTHENTICATION_STRING_DELIMITER) then
            raise Exception.Create('usingSalt must not contain DELIMITER 0x24 ($).');

        if (b = $27) then
            raise Exception.Create('usingSalt must not contain QUOTE 0x27 ('').');

        if (b = $5c) then
            raise Exception.Create('usingSalt must not contain BACKSLASH 0x5c (\).');
    end;
    
    Result := usingSalt;
end;

function TMySqlCredentials.AsCachingSha2Password(usingSalt : TBytes = nil) : string;
const ITERATION_MULTIPLIER : integer = 1000;
//const MAX_ITERATIONS : integer = 100000;

const STORED_SHA256_DIGEST_LENGTH : integer = 43;

const iterations : byte = 5; // actually: iterations * ITERATION_MULTIPLIER

const hashBits : integer = 256; // SHA256 output bits
const hashBytes : integer = 32; // hashBits / 8

// (hashBits == 256) SHA256 - define inc1, inc2, mod, end
const inc1 : integer = 10;
const inc2 : integer = 21;
const mod1 : integer = 30;
const end1 : integer = 0;

var saltBytes : TBytes;
    passwordBytes : TBytes;
    tmpBytes : TBytes;
    i : integer;
    til : integer;
    digest_b : TBytes;
    digest_a : TBytes;
    digest_dp : TBytes;
    sequence_p : TBytes;
    digest_ds : TBytes;
    sequence_s : TBytes;
    digest_c : TBytes;
    b64_result : TBytes;
begin
    // https://crypto.stackexchange.com/questions/77427/whats-the-algorithm-behind-mysqls-sha256-password-hashing-scheme
    // select user,host,convert(authentication_string using binary),plugin from mysql.user;

    saltBytes := GenerateSaltForCachingSha2Password(usingSalt);

    passwordBytes := ComputeStringToUtf8WithoutBom(Fpassword);

    //
    // Step 1 - digest_b
    //
    tmpBytes := concatBytes(passwordBytes, saltBytes, passwordBytes);
    digest_b := ComputeSha256(tmpBytes);
    
    //
    // Step 2 - digest_a
    //
    tmpBytes := concatBytes(passwordBytes, saltBytes);

    // Add for any character in the key one byte of the alternate sum.
    i := Length(passwordBytes);
    while (i > 0) do
    begin
        if (i > hashBytes) then
            tmpBytes := concatBytes(tmpBytes, digest_b)
        else
            tmpBytes := concatBytes(tmpBytes, sliceBytes(digest_b, 0, i));
            
        i := i - hashBytes;
    end;

    // Take the binary representation of the length of the key and for every 1 add the alternate sum, for every 0 the key.
    i := Length(passwordBytes);
    while (i > 0) do
    begin
        if ((i and 1) <> 0) then
            tmpBytes := concatBytes(tmpBytes, digest_b)
        else
            tmpBytes := concatBytes(tmpBytes, passwordBytes);
            
        i := i div 2;
    end;

    digest_a := ComputeSha256(tmpBytes);
    
    //
    // Step 3 - digest_dp
    //

    // For every character in the password add the entire password.
    tmpBytes := nil;
    
    i := 0;
    while(i < Length(passwordBytes)) do
    begin
        tmpBytes := concatBytes(tmpBytes, passwordBytes);
        
        i := i + 1;
    end;

    digest_dp := ComputeSha256(tmpBytes);
    
    //
    // Step 4 - sequence_p
    //
    sequence_p := nil;
    
    i := Length(passwordBytes);
    while (i > 0) do
    begin
        if (i > hashBytes) then
            sequence_p := concatBytes(sequence_p, digest_dp)
        else
            sequence_p := concatBytes(sequence_p, sliceBytes(digest_dp, 0, i));
            
        i := i - hashBytes;
    end;

    //
    // Step 5 - digest_ds
    //
    tmpBytes := nil;
    til := 16 + digest_a[0];
    
    i := 0;
    while (i < til) do
    begin
        tmpBytes := concatBytes(tmpBytes, saltBytes);
        
        i := i + 1;
    end;

    digest_ds := ComputeSha256(tmpBytes);

    //
    // Step 6 - sequence_s
    //
    sequence_s := nil;
    
    i := Length(saltBytes);
    while (i > 0) do
    begin
        if (i > hashBytes) then
            sequence_s := concatBytes(sequence_s, digest_ds)
        else
            sequence_s := concatBytes(sequence_s, sliceBytes(digest_ds, 0, i));
            
        i := i - hashBytes;
    end;
    
    //
    // Step 7 - now we do iterations into digest_c
    //
    digest_c := concatBytes(digest_a, nil);
    
    i := 0;
    while (i < (iterations * ITERATION_MULTIPLIER)) do
    begin
        if ((i and 1) <> 0) then
            tmpBytes := concatBytes(sequence_p, nil)
        else
            tmpBytes := concatBytes(digest_c, nil);

        if ((i mod 3) <> 0) then tmpBytes := concatBytes(tmpBytes, sequence_s);
        if ((i mod 7) <> 0) then tmpBytes := concatBytes(tmpBytes, sequence_p);

        if ((i and 1) <> 0) then
            tmpBytes := concatBytes(tmpBytes, digest_c)
        else
            tmpBytes := concatBytes(tmpBytes, sequence_p);

        digest_c := ComputeSha256(tmpBytes);
        
        i := i + 1;
    end;
    
    //
    // Step 8 - b64_result
    //

    b64_result := nil;
    i := 0;
    repeat
        b64_result := concatB64Encode(b64_result,
            (digest_c[i] shl 16) or (digest_c[(i + inc1) mod mod1] shl 8) or (digest_c[(i + (inc1 * 2)) mod mod1]), 4);
        i := (i + inc2) mod mod1;
    until (i = end1);

    // (hashBits == 256) SHA256
    b64_result := concatB64Encode(b64_result,
        (digest_c[31] shl 8) or (digest_c[30]), 3);

    if (Length(b64_result) <> STORED_SHA256_DIGEST_LENGTH) then
        raise Exception.Create('AsCachingSha2Password - b64_result must be ' + IntToStr(STORED_SHA256_DIGEST_LENGTH) + ' bytes, but is ' + IntToStr(Length(b64_result)) + '.');

    //
    // Step 9 - table "mysql.user", field "authentication_string" output
    //

    {
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
    }

    SetLength(tmpBytes, 7);
    tmpBytes[0] := AUTHENTICATION_STRING_DELIMITER; // $
    tmpBytes[1] := $41;      // A
    tmpBytes[2] := AUTHENTICATION_STRING_DELIMITER; // $
    tmpBytes[3] := byte($30 + ((iterations div 100) mod 10)); // 0
    tmpBytes[4] := byte($30 + ((iterations div 10) mod 10));  // 0
    tmpBytes[5] := byte($30 + ((iterations) mod 10));         // 5
    tmpBytes[6] := AUTHENTICATION_STRING_DELIMITER; // $
    tmpBytes := concatBytes(tmpBytes, saltBytes, b64_result);

    //return 0xAA... uppercase hex string
    Result := '0x' + ComputeBytesToUpperCaseHex(tmpBytes);
end;

function TMySqlCredentials.randomAsciiSalt(len : cardinal) : TBytes;
const _randomAsciiSalt_AllowedBytes : array[0..91] of byte = (
    // SALT bytes in ASCII range (and therefore also UTF-8) 0x20 - 0x7E with the exception of:
    // - DELIMITER $ (0x24)
    // - QUOTE ' (0x27) to prevent escaping problems.
    // - BACKSLASH \ (0x5c) to prevent escaping problems.
    // 92 bytes
    $20, $21, $22, $23, { $} $25, $26, {'}  $28, $29, $2a, $2b, $2c, $2d, $2e, $2f,
    $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $3a, $3b, $3c, $3d, $3e, $3f,
    $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $4a, $4b, $4c, $4d, $4e, $4f,
    $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $5a, $5b, {\}  $5d, $5e, $5f,
    $60, $61, $62, $63, $64, $65, $66, $67, $68, $69, $6a, $6b, $6c, $6d, $6e, $6f,
    $70, $71, $72, $73, $74, $75, $76, $77, $78, $79, $7a, $7b, $7c, $7d, $7e
);

//   0 ..  91
//  92 .. 183
// 184 .. 275 !!! bias, because the random range is 0..255 (a byte). The values 256..275 don't have a chance to get choosen.
const maxUnbiased : cardinal = 183;
    
var _randomPool : TBytes;
    _randomPoolIdx : cardinal;
    _random : byte;
    idx : cardinal;
begin
    SetLength(Result, len);
    
    _randomPool := nil;
    _randomPoolIdx := 0;

    idx := 0;
    while (idx < len) do
    begin
        if (_randomPoolIdx >= cardinal(Length(_randomPool))) then
            begin
                _randomPool := ComputeSecureRandomBytes(len);
                _randomPoolIdx := 0;
            end;
        _random := _randomPool[_randomPoolIdx];
        _randomPoolIdx := _randomPoolIdx + 1;

        if (_random <= maxUnbiased) then
            begin
                result[idx] := _randomAsciiSalt_AllowedBytes[_random mod Length(_randomAsciiSalt_AllowedBytes)];
                idx := idx + 1;
            end;
    end;
end;    

function TMySqlCredentials.B64Encode(valueToConvertToB64 : integer; n : integer) : TBytes;
const _B64Encode_Table : array[0..63] of byte = (
    // ('.', '/', '0' ..'9', 'A' .. 'Z', 'a' .. 'z')
    $2e, $2f,

    $30, $31, $32, $33, $34, $35, $36, $37, $38, $39,

    $41, $42, $43, $44, $45, $46, $47, $48, $49, $4a, $4b, $4c, $4d, $4e, $4f, $50,
    $51, $52, $53, $54, $55, $56, $57, $58, $59, $5a,

    $61, $62, $63, $64, $65, $66, $67, $68, $69, $6a, $6b, $6c, $6d, $6e, $6f, $70,
    $71, $72, $73, $74, $75, $76, $77, $78, $79, $7a
);

var encoded : TBytes;
    i : integer;
begin
    // returns bytes in ASCII range (and therefore also UTF-8)
    SetLength(encoded, n);
    i := 0;
    while (i < n) do
    begin
        encoded[i] := _B64Encode_Table[valueToConvertToB64 and $3f];
        valueToConvertToB64 := valueToConvertToB64 shr 6;
        
        i := i + 1;
    end;

    Result := encoded;
end;

function TMySqlCredentials.ComputeBytesToUpperCaseHex(value : TBytes) : string;
const HexChars : Array[0..15] of Char = ('0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F');
var i : integer;
begin
    Result := '';
    for i:=Low(value) to High(value) do
    begin
        Result := Result + HexChars[(value[i] shr 4) and $0f] + HexChars[value[i] and $0f];
    end;
end;

type TUTF8EncodingWithoutBom = class(TUTF8Encoding)
public
    function GetPreamble(): TBytes; override;
end;

function TUTF8EncodingWithoutBom.GetPreamble(): TBytes;
begin
    Result := nil;
end;

function TMySqlCredentials.ComputeStringToUtf8WithoutBom(value : string) : TBytes;
var Utf8WithoutBom : TUTF8EncodingWithoutBom;
begin
    Utf8WithoutBom := TUTF8EncodingWithoutBom.Create();
    try
        Result := Utf8WithoutBom.GetBytes(value);
    finally
        FreeAndNil(Utf8WithoutBom);
    end;
end;

function TMySqlCredentials.ComputeSha1(value : TBytes) : TBytes;
var sha1 : THashSha1;
begin
    sha1 := THashSha1.Create();
    sha1.Update(value, Length(value));
    
    Result := sha1.HashAsBytes();
end;

function TMySqlCredentials.ComputeSha256(value : TBytes) : TBytes;
var sha256 : THashSha2;
begin
    sha256 := THashSha2.Create(THashSha2.TSHA2Version.SHA256);
    sha256.Update(value, Length(value));
    
    Result := sha256.HashAsBytes();
end;

// ComputeSecureRandomBytes() via Windows Crypto Api
type HCRYPTPROV = pointer;
type TCryptAcquireContextA = function(var phProv: HCRYPTPROV; pszContainer: PAnsiChar; pszProvider: PAnsiChar; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall;
type TCryptGenRandom = function(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: Pointer): BOOL; stdcall;
type TCryptReleaseContext = function(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall;

const PROV_RSA_FULL = 1;
const CRYPT_VERIFYCONTEXT = $F0000000;

var AdvApiLoaded: boolean;
var AdvApiHandle: HModule;
var CryptAcquireContextA : TCryptAcquireContextA;
var CryptGenRandom : TCryptGenRandom;
var CryptReleaseContext : TCryptReleaseContext;

function TMySqlCredentials.ComputeSecureRandomBytes(len : cardinal) : TBytes;
    function LoadAdvApi() : boolean; inline;
    begin
        if not AdvApiLoaded then
            begin
                AdvApiLoaded := true;

                AdvApiHandle := LoadLibrary('advapi32.dll');
                if AdvApiHandle <> 0 then
                    begin
                        CryptAcquireContextA := GetProcAddress(AdvApiHandle,'CryptAcquireContextA');
                        CryptGenRandom := GetProcAddress(AdvApiHandle,'CryptGenRandom');
                        CryptReleaseContext := GetProcAddress(AdvApiHandle,'CryptReleaseContext');
                    end;
            end;

        Result := Assigned(CryptAcquireContextA) and Assigned(CryptGenRandom) and Assigned(CryptReleaseContext);
    end;

var hProv : HCRYPTPROV;
begin
    if not LoadAdvApi() then
        begin
            raise Exception.Create('Error loading advapi32.dll');
        end;

    hProv := nil;
    if not CryptAcquireContextA(hProv,
                                nil,
                                nil,
                                PROV_RSA_FULL,
                                CRYPT_VERIFYCONTEXT) then
        begin
            RaiseLastOSError();
        end;

    try
        SetLength(Result, len);

        if not CryptGenRandom(hProv, len, @Result[0]) then
            begin
                RaiseLastOSError();
            end;
    finally
        CryptReleaseContext(hProv, 0);
    end;
end;

function TMySqlCredentials.sliceBytes(bytes : TBytes; offset : integer; count : integer) : TBytes;
begin
    SetLength(Result, count);
    if (count > 0) then
        Move(bytes[offset], Result[0], count);
end;

function TMySqlCredentials.concatBytes(bytes1 : TBytes; bytes2 : TBytes) : TBytes;
begin
    SetLength(Result, Length(bytes1) + Length(bytes2));
    if (Length(bytes1) > 0) then
        Move(bytes1[0], Result[0], Length(bytes1));
    if (Length(bytes2) > 0) then
        Move(bytes2[0], Result[Length(bytes1)], Length(bytes2));
end;

function TMySqlCredentials.concatBytes(bytes1 : TBytes; bytes2 : TBytes; bytes3 : TBytes) : TBytes;
begin
    SetLength(Result, Length(bytes1) + Length(bytes2) + Length(bytes3));
    if (Length(bytes1) > 0) then
        Move(bytes1[0], Result[0], Length(bytes1));
    if (Length(bytes2) > 0) then
        Move(bytes2[0], Result[Length(bytes1)], Length(bytes2));
    if (Length(bytes3) > 0) then
        Move(bytes3[0], Result[Length(bytes1) + Length(bytes2)], Length(bytes3));
end;

function TMySqlCredentials.concatB64Encode(bytes : TBytes; valueToConvertToB64 : integer; n : integer) : TBytes;
begin
    Result := concatBytes(bytes, B64Encode(valueToConvertToB64, n));
end;

begin
    AdvApiLoaded := false;
    AdvApiHandle := 0;
    CryptAcquireContextA := nil;
    CryptGenRandom := nil;
    CryptReleaseContext := nil;
end.