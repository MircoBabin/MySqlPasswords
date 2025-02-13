@echo off
setlocal
cls

cd /D "%~dp0"


set sz_exe=C:\Program Files\7-Zip\7z.exe
if exist "%sz_exe%" goto build

set sz_exe=C:\Program Files (x86)\7-Zip\7z.exe
if exist "%sz_exe%" goto build

echo !!! 7-Zip 18.06 - 7z.exe not found
pause
goto:eof

:build 
echo 7-Zip 18.06: %sz_exe%

:build_zip
del /q "%~dp0Release\*" >nul 2>&1

"%sz_exe%" a -tzip -mx7 "%~dp0Release\MySqlPasswords.zip" "%~dp0..\bin\CSharp\Release\MySqlPasswords.exe" "%~dp0..\bin\CSharp\Release\MySqlPasswords.exe.config"

copy /y "%~dp0..\docs\CSharp.md" "%~dp0Release\MySqlCredentials-CSharp-readme.md" >nul
"%sz_exe%" a -tzip -mx7 "%~dp0Release\MySqlCredentials-CSharp.zip" "%~dp0..\src\CSharp\MySqlPasswords\MySqlCredentials.cs" "%~dp0Release\MySqlCredentials-CSharp-readme.md"
del /q "%~dp0Release\MySqlCredentials-CSharp-readme.md" >nul 2>&1

copy /y "%~dp0..\docs\Delphi.md" "%~dp0Release\MySqlCredentials-Delphi-readme.md" >nul
"%sz_exe%" a -tzip -mx7 "%~dp0Release\MySqlCredentials-Delphi.zip" "%~dp0..\src\Delphi\MySqlPasswords\MySqlCredentials.pas" "%~dp0Release\MySqlCredentials-Delphi-readme.md"
del /q "%~dp0Release\MySqlCredentials-Delphi-readme.md" >nul 2>&1

copy /y "%~dp0..\docs\Php.md" "%~dp0Release\MySqlCredentials-Php-readme.md" >nul
"%sz_exe%" a -tzip -mx7 "%~dp0Release\MySqlCredentials-Php.zip" "%~dp0..\src\Php\MySqlCredentials.php" "%~dp0Release\MySqlCredentials-Php-readme.md"
del /q "%~dp0Release\MySqlCredentials-Php-readme.md" >nul 2>&1

echo.
echo.
echo Created "Release\*.zip"

pause
goto :eof
