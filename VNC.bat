@echo off
rem Kept for people who used the 0.2 batch file.  The 2.0 tool does not need a
rem wrapper: run "vncpwd.exe scan" to inspect this machine, or
rem "vncpwd.exe inspect --hex <value>" to check a single stored password.
rem
rem The old 0.2 batch file stored the result in t.txt; this version prints to
rem the console and never writes passwords to disk.
vncpwd.exe scan
pause
