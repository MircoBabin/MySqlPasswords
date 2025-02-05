[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/MircoBabin/MySqlPasswords/blob/master/LICENSE.md)

# MySql Passwords
MySql Passwords is a tool for calculating the MySql hash of mysql_native_password and caching_sha2_password password plugins. This is the authentication_string field in the mysql.user table.

# Programming language

- [Documentation for C#.](docs/CSharp.md)

# Why

The next sql statements are not secure, because they send the password 'secret' in plain text to the MySql server. The tcp/ip connection maybe compromised, allowing an attacker to sniff the plain text password. The statement maybe logged or maybe disclosed in other ways.

```sql
CREATE USER 'root'@'%' IDENTIFIED BY 'secret'; -- !!! INSECURE !!!

ALTER USER 'root'@'%' IDENTIFIED BY 'secret'; -- !!! INSECURE !!!
```

Changing the password of a MySql user in a secure way, requires calculating the hash of the password. So the password is send as a hash to the MySql server and not in plain text anymore. The next commands send the value of authentication_string in the mysql.user table. Which is secure, even if intercepted by an attacker or logged or ....

```sql
CREATE USER 'root'@'%' IDENTIFIED WITH caching_sha2_password AS 0x24412430303524517D22565B3D67635E4136625E414272223A522F373248496B496B7368563976366D73677476794E6F574C6C4346554662416E66753746637958455047332E;

ALTER USER 'root'@'%' IDENTIFIED WITH caching_sha2_password AS 0x24412430303524517D22565B3D67635E4136625E414272223A522F373248496B496B7368563976366D73677476794E6F574C6C4346554662416E66753746637958455047332E;
```

Calculating the correct hash of plain text password is not well documented by the MySql team. After some investigation I managed to retrieve the algorithm for:

- caching_sha2_password. Recommended.
- mysql_native_password. Deprecated. Disabled by default from MySql 8.4. And removed from MySql 9.0.

# Contributions
Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md "contributing") before making any contribution!

# License
[The license is MIT.](LICENSE.md "license")





