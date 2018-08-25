@echo off
set /p pass=Please input a password:
vncpwd.exe %pass% >> t.txt