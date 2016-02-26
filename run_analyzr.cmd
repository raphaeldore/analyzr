@echo off

REM python-env\Scripts\python.exe -m scripts.analyzrctl %*

py-env-analyzr\Scripts\python.exe  %~dp0\analyzr.py %*

PAUSE