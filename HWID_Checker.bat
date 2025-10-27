@echo off
title HWID Checker by 3la2

@echo SMBIOS
@echo off 
wmic csproduct get uuid

@echo BIOS
@echo off 
wmic bios get serialnumber

@echo MOTHERBOARD
@echo off 
wmic baseboard get serialnumber

@echo Chassis
@echo off
wmic systemenclosure get serialnumber

@echo CPU
@echo off 
wmic cpu get serialnumber


@echo VOLUME
@echo off 
vol
echo.




@echo MAC ADRESSES
@echo off 
getmac
echo.

cmd /k
