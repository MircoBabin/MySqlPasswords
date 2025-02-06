program MySqlPasswords;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  MySqlCredentials in 'MySqlCredentials.pas',
  ProgramMain in 'ProgramMain.pas';

var args : array of string;
var i : integer;
begin
    try
        SetLength(args, System.ParamCount);
        for i := 1 to System.ParamCount do
        begin
            args[i-1] := System.ParamStr(i);
        end;

        Main(args);
    except
        on E: Exception do
            Writeln(E.ClassName, ': ', E.Message);
    end;
end.
