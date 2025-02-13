<?php

require_once __DIR__.'/MySqlCredentials.php';

function OutputHelp()
{
    echo 'usage:'.PHP_EOL;
    echo 'MySqlPasswords username password {-host %} {-salt caching-sha2-salt-20-characters}'.PHP_EOL;
    echo PHP_EOL;
    echo 'e.g.'.PHP_EOL;
    echo '- MySqlPasswords test secret'.PHP_EOL;
    echo '- MySqlPasswords root2 secret-root2-password -salt ABCDEFGHIJKLMNOPQRST'.PHP_EOL;
    echo '- MySqlPasswords root2 secret-root2-password -host localhost -salt ABCDEFGHIJKLMNOPQRST'.PHP_EOL;
    echo PHP_EOL;
    echo '{-salt caching-sha2-salt-20-characters} must only be provided for testing purposes. When not provided it will be randomly generated, enhancing the security.'.PHP_EOL;
}

function OutputPassword($warning, $credentials, $passwordPluginType, $salt)
{
    $saltBytes = $credentials->GenerateSaltForCachingSha2Password($salt);

    $sql = '';

    echo '----------------------------------------------'.PHP_EOL;
    switch ($passwordPluginType) {
        case \MySqlServer\MySqlCredentials::MySqlPluginType_caching_sha2_password:
            echo '--- caching_sha2_password'.PHP_EOL;
            break;

        case \MySqlServer\MySqlCredentials::MySqlPluginType_mysql_native_password:
            echo '--- mysql_native_password'.PHP_EOL;
            break;

        default:
            echo '--- '.$passwordPluginType.PHP_EOL;
    }
    echo '----------------------------------------------'.PHP_EOL;
    if (null !== $warning && '' !== $warning) {
        echo $warning.PHP_EOL;
    }
    echo PHP_EOL;

    echo '* Create user'.PHP_EOL;
    $sql = '';
    $sql .= $credentials->GetSqlForDropUser(true);
    $sql .= PHP_EOL;

    $sql .= $credentials->GetSqlForCreateUser(false, $passwordPluginType, $saltBytes);
    $sql .= PHP_EOL;
    echo $sql;
    echo PHP_EOL;

    echo '* Change existing password'.PHP_EOL;
    $sql = '';
    $sql .= $credentials->GetSqlForAlterUserPassword(false, $passwordPluginType, $saltBytes);
    $sql .= PHP_EOL;
    echo $sql;
    echo PHP_EOL;
}

function OutputPlainPassword($credentials)
{
    $sql = '';

    echo '----------------------------------------------'.PHP_EOL;
    echo '--- as plaintext in IDENTIFIED BY clause'.PHP_EOL;
    echo '----------------------------------------------'.PHP_EOL;
    echo '!!! Do not use, this is insecure. This sends password in plaintext to MySql server!'.PHP_EOL;
    echo PHP_EOL;

    $sql = '';
    $sql .= $credentials->GetSqlForAlterUserPassword(false, \MySqlServer\MySqlCredentials::MySqlPluginType_default_with_password_in_plaintext, null);
    $sql .= PHP_EOL;
    echo $sql;
    echo PHP_EOL;
}

function Main($args)
{
    echo 'MySqlPasswords 1.0'.PHP_EOL;
    echo 'https://github.com/MircoBabin/MySqlPasswords - MIT license'.PHP_EOL;
    echo PHP_EOL;

    if (count($args) < 2) {
        OutputHelp();
        exit(99);
    }

    $username = $args[0];
    $password = $args[1];
    $host = '%';
    $salt = null;

    if (count($args) >= 4) {
        if ('-host' == $args[2]) {
            $host = $args[3];
        } elseif ('-salt' == $args[2]) {
            $salt = $args[3];
        }
    }

    if (count($args) >= 6) {
        if ('-host' == $args[4]) {
            $host = $args[5];
        } elseif ('-salt' == $args[4]) {
            $salt = $args[5];
        }
    }

    $credentials = new \MySqlServer\MySqlCredentials($username, $password, \MySqlServer\MySqlCredentials::PasswordType_Sensitive);
    $credentials->host = $host;
    OutputPassword(null,
        $credentials, \MySqlServer\MySqlCredentials::MySqlPluginType_caching_sha2_password, $salt);

    OutputPassword('!!! Warning: mysql_native_plugin is deprecated and removed from MySql 9.0!',
        $credentials, \MySqlServer\MySqlCredentials::MySqlPluginType_mysql_native_password, null);

    OutputPlainPassword($credentials);

    exit(0);
}

$arguments = $argv;
array_shift($arguments); // remove [0] the name that was used to run the script
Main($arguments);
