unit ProgramMain;

interface

procedure Main(args : array of string);

implementation
uses SysUtils, MySqlCredentials, System.TypInfo, Windows;

const NewLine = #13#10;

procedure OutputHelp();
begin
    WriteLn('MySqlPasswords 1.0');
    WriteLn('');
    WriteLn('usage:');
    WriteLn('MySqlPasswords username password {-host %} {-salt caching-sha2-salt-20-characters}');
    WriteLn('');
    WriteLn('e.g.');
    WriteLn('- MySqlPasswords test secret');
    WriteLn('- MySqlPasswords root2 secret-root2-password -salt ABCDEFGHIJKLMNOPQRST');
    WriteLn('- MySqlPasswords root2 secret-root2-password -host localhost -salt ABCDEFGHIJKLMNOPQRST');
    WriteLn('');
    WriteLn('{-salt caching-sha2-salt-20-characters} must only be provided for testing purposes. When not provided it will be randomly generated, enhancing the security.');
end;

procedure OutputPassword(warning : string; credentials : TMySqlCredentials; passwordPluginType : TMySqlCredentials.TMySqlPluginType; salt : string);
var saltBytes : TBytes;
    sql : string;
begin
    saltBytes := credentials.GenerateSaltForCachingSha2Password(salt);

    WriteLn('----------------------------------------------');
    WriteLn('--- ' + GetEnumName(TypeInfo(TMySqlCredentials.TMySqlPluginType), Integer(passwordPluginType)));
    WriteLn('----------------------------------------------');
    if (warning <> '') then
        WriteLn(warning);
    WriteLn('');

    WriteLn('* Create user');
    sql := '';
    sql := sql + credentials.GetSqlForDropUser(true);
    sql := sql + NewLine;

    sql := sql + credentials.GetSqlForCreateUser(false, passwordPluginType, saltBytes);
    sql := sql + NewLine;
    Write(sql);
    WriteLn('');

    WriteLn('* Change existing password');
    sql := '';
    sql := sql + credentials.GetSqlForAlterUserPassword(false, passwordPluginType, saltBytes);
    sql := sql + NewLine;
    Write(sql);
    WriteLn('');
end;

procedure OutputPlainPassword(credentials : TMySqlCredentials);
var sql : string;
begin
    WriteLn('----------------------------------------------');
    WriteLn('--- as plaintext in IDENTIFIED BY clause');
    WriteLn('----------------------------------------------');
    WriteLn('!!! Do not use, this is insecure. This sends password in plaintext to MySql server!');
    WriteLn('');

    sql := '';
    sql := sql + credentials.GetSqlForAlterUserPassword(false, TMySqlCredentials.TMySqlPluginType.default_with_password_in_plaintext, nil);
    sql := sql + NewLine;
    Write(sql);
    WriteLn('');
end;

procedure Main(args : array of string);
var username : string;
    password : string;
    host : string;
    salt : string;
    credentials : TMySqlCredentials;
begin
    if (Length(args) < 2) then
    begin
        OutputHelp();
        Halt(99);
    end;

    username := args[0];
    password := args[1];
    host := '%';
    salt := '';

    if (Length(args) >= 4) then
    begin
        if (args[2] = '-host') then
            host := args[3]
        else if (args[2] = '-salt') then
            salt := args[3];
    end;

    if (Length(args) >= 6) then
    begin
        if (args[4] = '-host') then
            host := args[5]
        else if (args[4] = '-salt') then
            salt := args[5];
    end;


    credentials := TMySqlCredentials.Create(username, password, TMySqlCredentials.TPasswordType.Sensitive);
    try
        credentials.host := host;
        OutputPassword('',
            credentials, TMySqlCredentials.TMySqlPluginType.caching_sha2_password, salt);

        OutputPassword('!!! Warning: mysql_native_plugin is deprecated and removed from MySql 9.0!',
            credentials, TMySqlCredentials.TMySqlPluginType.mysql_native_password, '');

        OutputPlainPassword(credentials);
    finally
        FreeAndNil(credentials);
    end;

    if (IsDebuggerPresent()) then
        begin
            WriteLn('Press the ENTER key to exit.');
            ReadLn(System.Input);
        end;

    Halt(0);
end;

end.
