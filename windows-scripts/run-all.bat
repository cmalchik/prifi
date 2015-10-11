@echo off

ECHO Low Latency Dissent
ECHO ...

ECHO Starting the relay... [might prompt for UAC, please accept]
start relay.bat
pause

ECHO Starting the trustee 0...
start trustee0.bat
ping -n 2 127.0.0.1 >nul

ECHO Starting the trustee 1...
start trustee1.bat
ping -n 2 127.0.0.1 >nul

ECHO Starting the trustee 2...
start trustee2.bat
ping -n 2 127.0.0.1 >nul

ECHO Starting the client 0... [might prompt for UAC, please accept]
start client0.bat
pause