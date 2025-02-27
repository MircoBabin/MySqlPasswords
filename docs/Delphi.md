# Delphi

```pas
uses MySqlCredentials;

var credentials : TMySqlCredentials;
var sql : string;
begin
    credentials := TMySqlCredentials.Create('root', 'password', TMySqlCredentials.TPasswordType.Sensitive);
    credentials.host := '%';

    //
    // DROP USER IF EXISTS ...; 
    // CREATE USER ....;
    //
    sql := '';
    sql := sql + credentials.GetSqlForDropUser(true);
    sql := sql + credentials.GetSqlForCreateUser(false, TMySqlCredentials.TMySqlPluginType.caching_sha2_password);
    // execute sql



    //
    // ALTER USER ...;
    //
    sql := '';
    sql := sql + credentials.GetSqlForAlterUser(false, TMySqlCredentials.TMySqlPluginType.caching_sha2_password);
    // execute sql
end;    
```

# Installation

Include [MySqlCredentials.pas](https://github.com/MircoBabin/MySqlPasswords/releases/latest/download/MySqlCredentials-Delphi.zip) in your project.

# Extra fields

These fields are only included for convenience. To collect all possible MySql login properties into one class.

- ```passwordtype``` can be set to indicate it is an Empty, Sensitive (a real password) or NotSensitive (maybe used directly on the commandline, if it leaks not a problem) password. This field is not actually used.
- ```sslCaCertFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```sslClientCertFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```sslClientKeyFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```host``` can be set to "%" meaning any connection, "localhost" meaning only on the MySql server machine or some other value. This field is only used when dropping/creating/altering the user. It is not needed for login to MySql server.
