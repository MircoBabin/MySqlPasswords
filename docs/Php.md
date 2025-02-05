# Php

```php
<?php
require_once(__DIR__.'/MySqlCredentials.php');

$credentials = new \MySqlServer\MySqlCredentials('root', 'password', \MySqlServer\MySqlCredentials::PasswordType_Sensitive);
$credentials->host = "%";

//
// DROP USER IF EXISTS ...; 
// CREATE USER ....;
//
$sql = '';
$sql .= $credentials->GetSqlForDropUser(true).PHP_EOL;
$sql .= $credentials->GetSqlForCreateUser(false, \MySqlServer\MySqlCredentials::MySqlPluginType_caching_sha2_password).PHP_EOL;
// execute sql



//
// ALTER USER ...;
//
$sql = '';
$sql .= $credentials.GetSqlForAlterUser(false, \MySqlServer\MySqlCredentials::MySqlPluginType_caching_sha2_password).PHP_EOL;
// execute sql
```

# Installation

Include [MySqlCredentials.php](../src/Php/MySqlCredentials.php) in your project. And maybe adjust the namespace.

# Extra fields

These fields are only included for convenience. To collect all possible MySql login properties into one class.

- ```passwordtype``` can be set to indicate it is an Empty, Sensitive (a real password) or NotSensitive (maybe used directly on the commandline, if it leaks not a problem) password. This field is not actually used.
- ```sslCaCertFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```sslClientCertFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```sslClientKeyFilename``` can be set for a (ssl) client certificate. This field is not actually used.
- ```host``` can be set to "%" meaning any connection, "localhost" meaning only on the MySql server machine or some other value. This field is only used when dropping/creating/altering the user. It is not needed for login to MySql server.
