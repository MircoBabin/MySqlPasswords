using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MySqlPasswords
{
    class Program
    {
        private static void OutputHelp()
        {
            Console.Out.WriteLine("MySqlPasswords 1.0");
            Console.Out.WriteLine();
            Console.Out.WriteLine("usage:");
            Console.Out.WriteLine("MySqlPasswords username password {-host %} {-salt caching-sha2-salt-20-characters}");
            Console.Out.WriteLine();
            Console.Out.WriteLine("e.g.");
            Console.Out.WriteLine("- MySqlPasswords test secret");
            Console.Out.WriteLine("- MySqlPasswords root2 secret-root2-password -salt ABCDEFGHIJKLMNOPQRST");
            Console.Out.WriteLine("- MySqlPasswords root2 secret-root2-password -host localhost -salt ABCDEFGHIJKLMNOPQRST");
            Console.Out.WriteLine();
            Console.Out.WriteLine("{-salt caching-sha2-salt-20-characters} must only be provided for testing purposes. When not provided it will be randomly generated, enhancing the security.");
        }

        private static void OutputPassword(string warning, MySqlServer.MySqlCredentials credentials, MySqlServer.MySqlCredentials.MySqlPluginType passwordPluginType, string salt)
        {
            byte[] saltBytes = credentials.GenerateSaltForCachingSha2Password(salt);

            StringBuilder sql = new StringBuilder();

            Console.Out.WriteLine("----------------------------------------------");
            Console.Out.WriteLine("--- " + passwordPluginType.ToString());
            Console.Out.WriteLine("----------------------------------------------");
            if (!string.IsNullOrEmpty(warning))
                Console.Out.WriteLine(warning);
            Console.Out.WriteLine();

            Console.Out.WriteLine("* Create user");
            sql.Clear();
            sql.Append(credentials.GetSqlForDropUser(true));
            sql.Append(Environment.NewLine);

            sql.Append(credentials.GetSqlForCreateUser(false, passwordPluginType, saltBytes));
            sql.Append(Environment.NewLine);
            Console.Out.Write(sql);
            Console.Out.WriteLine();

            Console.Out.WriteLine("* Change existing password");
            sql.Clear();
            sql.Append(credentials.GetSqlForAlterUserPassword(false, passwordPluginType, saltBytes));
            sql.Append(Environment.NewLine);
            Console.Out.Write(sql);
            Console.Out.WriteLine();
        }

        private static void OutputPlainPassword(MySqlServer.MySqlCredentials credentials)
        {
            StringBuilder sql = new StringBuilder();

            Console.Out.WriteLine("----------------------------------------------");
            Console.Out.WriteLine("--- as plaintext in IDENTIFIED BY clause");
            Console.Out.WriteLine("----------------------------------------------");
            Console.Out.WriteLine("!!! Do not use, this is insecure. This sends password in plaintext to MySql server!");
            Console.Out.WriteLine();

            sql.Clear();
            sql.Append(credentials.GetSqlForAlterUserPassword(false, MySqlServer.MySqlCredentials.MySqlPluginType.default_with_password_in_plaintext, null));
            sql.Append(Environment.NewLine);
            Console.Out.Write(sql);
            Console.Out.WriteLine();
        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                OutputHelp();
                Environment.Exit(99);
            }

            string username = args[0];
            string password = args[1];
            string host = "%";
            string salt = null;

            if (args.Length >= 4)
            { 
                if (args[2] == "-host")
                    host = args[3];
                else if (args[2] == "-salt")
                    salt = args[3];
            }

            if (args.Length >= 6)
            {
                if (args[4] == "-host")
                    host = args[5];
                else if (args[4] == "-salt")
                    salt = args[5];
            }

            var credentials = new MySqlServer.MySqlCredentials(username, password, MySqlServer.MySqlCredentials.PasswordType.NotSensitive);
            credentials.host = host;
            OutputPassword(null,
                credentials, MySqlServer.MySqlCredentials.MySqlPluginType.caching_sha2_password, salt);

            OutputPassword("!!! Warning: mysql_native_plugin is deprecated and removed from MySql 9.0!",
                credentials, MySqlServer.MySqlCredentials.MySqlPluginType.mysql_native_password, null);

            OutputPlainPassword(credentials);

            if (System.Diagnostics.Debugger.IsAttached)
                Console.ReadKey();

            Environment.Exit(0);
        }
    }
}
