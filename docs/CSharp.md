# C#

```cs
var credentials = new MySqlServer.MySqlCredentials("root", "password", MySqlServer.MySqlCredentials.PasswordType.Sensitive);
credentials.host = "%";

StringBuilder sql = new StringBuilder();

//
// DROP USER IF EXISTS ...; 
// CREATE USER ....;
//
sql.Clear();
sql.AppendLine(credentials.GetSqlForDropUser(true));
sql.AppendLine(credentials.GetSqlForCreateUser(false, MySqlServer.MySqlCredentials.MySqlPluginType.caching_sha2_password));
// execute sql



//
// ALTER USER ...;
//
sql.Clear();
sql.AppendLine(credentials.GetSqlForAlterUser(false, MySqlServer.MySqlCredentials.MySqlPluginType.caching_sha2_password));
// execute sql
```

# Installation

Include [MySqlCredentials.cs](https://github.com/MircoBabin/MySqlPasswords/releases/latest/download/MySqlCredentials-CSharp.zip) in your project. And maybe adjust the namespace.

# Extra fields

These fields are only included for convenience. To collect all possible MySql login properties into one class.

- ```passwordtype``` can be set to indicate it is an Empty, Sensitive (a real password) or NotSensitive (maybe used directly on the commandline, if it leaks not a problem) password. This field is not actually used.
- ```sslCaCertFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```sslClientCertFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```sslClientKeyFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```host``` can be set to "%" meaning any connection, "localhost" meaning only on the MySql server machine or some other value. This field is only used when dropping/creating/altering the user. It is not needed for login to MySql server.
