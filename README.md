# VSEM - Vcudachi Session Enumeration Module
## Description
This module contains cmdlets designed to retrieve information about user and other sessions on the local machine via API Win32:
* NetWkstaUserEnum
* NetSessionEnum
* WTSEnumerateSessionsExW
* LsaGetLogonSessionData

## Important information
* This module is canonical because does not contain C# code snippets. 
* This module supports Windows platform only.
* This module supports i86-x64 platform only, **do not run in 32-bit powershell**.
* This module supports Powershell 5.1 and Powershell 7. Powershell 5.1 is minimal requirement.

## Created by
- vcudachi

## Special thx to
- https://t.me/ru_powershell
- https://learn.microsoft.com/
- https://poshsecurity.com/blog/2014/2/3/powershell-error-the-specified-structure-must-be-blittable-o.html
- Google Search
