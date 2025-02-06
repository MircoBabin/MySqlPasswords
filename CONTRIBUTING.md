# MySqlPasswords contributions

All contributions are accepted under [the MIT license](LICENSE.md "license").

## Rules

For each contribution the following rules apply:

1. The contribution must provide something meaningful to the end user, who is using MySql server.
  * Adding a new programming language will be accepted. If the layout and implementation of the functions/class resembles the C# [MySqlCredentials.cs](src/CSharp/MySqlPassword/MySqlCredentials.cs) implementation.
  * Internal refactorings will not be accepted. They are not meaningful to the end user.
  * Internal reorganisation of the files/maps structure will not be accepted. It is not meaningful to the end user.
  * Unit Tests / Tests may be accepted. Each contributed test will be examined seperatly.
  
2. The project should compile out of the box, without additional download.
  * After cloning this project to a local harddisk, no additional downloads must be necessary. The project must compile at once.
  * NuGet/Composer packages download are forbidden.
  * NuGet/Composer packages are not forbidden, as long as they are inside the project and not downloaded.

**If one or more of these rules violates the principles/preferences of a person, that person is adviced to fork this project. And change the fork to his/her preferences.**