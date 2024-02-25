#requires -version 5.1
<#
.SYNOPSIS
  VSEM - Vcudachi Session Enumeration Module
.DESCRIPTION
  This module contains cmdlets designed to retrieve information about user and other sessions on the local machine via API Win32:
    NetWkstaUserEnum
    NetSessionEnum
    WTSEnumerateSessionsExW
    LsaGetLogonSessionData
  This module is canonical because does not contain C# code snippets. 
  This module supports Windows platform only.
  This module supports unicode platform only, do not run in non-unicode environment.
  This module supports Powershell 5.1 and Powershell 7. Powershell 5.1 is minimal requirement.
.NOTES
  Version:        1.1
  Author:         vcudachi
  Creation Date:  2024-0207@1805
  License:        MIT
  
.EXAMPLE
  To get session info:
  Get-VSEMWkstaLoggedOnUsers | Out-GridView
  Get-VSEMNetSessions | Out-GridView
  Get-VSEMTSSessions | Out-GridView
  Get-VSEMSecSessions | Out-GridView

  To logoff user:
  Get-VSEMTSSessions | Where-Object {$_.UserName -eq 'John' -and $_.DomainName -eq 'CONTOSO'} | Invoke-VSEMTSLogoffSession -Wait
#>

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#Creates in-memory module VSEM and populates it with Win32 functions, enums and structures
#Does not support powershell prior to 5.1 because of .NET Framework 4.7 usage
Function Import-VSEModule {
    Try {
        #Security checks
        If ($PSVersionTable.PSVersion -lt [Version]'5.1') {
            Return [UInt32]'0xffffffff'
        }
        $TestCount = 0
        Try {
            $null = [VSEM.Netapi32]
        }
        Catch {
            $TestCount++
        }
        Try {
            $null = [VSEM.wtsapi32]
        }
        Catch {
            $TestCount++
        }
        Try {
            $null = [VSEM.Secur32]
        }
        Catch {
            $TestCount++
        }
        If ($TestCount -eq 0) {
            Return [UInt32]'0x0'
        }
        ElseIf ($TestCount -gt 0 -and $TestCount -lt 3) {
            Return [UInt32]'0xffffffff'
        }

        #In-memory module builder
        $ModuleName = 'VSEM' #Vcudachi Session Enumeration Module
        $AssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($ModuleName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName)
    
        $DllImport = [Runtime.InteropServices.DllImportAttribute]
        $SetLastErrorField = $DllImport.GetField('SetLastError')
        $CallingConventionField = $DllImport.GetField('CallingConvention')
        $CharsetField = $DllImport.GetField('CharSet')
        $EntryPointField = $DllImport.GetField('EntryPoint')
        $SLEValue = $True
        $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])

        #Enum WTS_CONNECTSTATE_CLASS https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_connectstate_class
        $WTS_CONNECTSTATE_CLASS_TypeBuilder = $ModuleBuilder.DefineEnum("$ModuleName.WTS_CONNECTSTATE_CLASS", 'Public', [UInt16])
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSActive', [UInt16] 0)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSConnected', [UInt16] 1)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSConnectQuery', [UInt16] 2)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSShadow', [UInt16] 3)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSDisconnected', [UInt16] 4)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSIdle', [UInt16] 5)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSListen', [UInt16] 6)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSReset', [UInt16] 7)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSDown', [UInt16] 8)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.DefineLiteral('WTSInit', [UInt16] 9)
        $null = $WTS_CONNECTSTATE_CLASS_TypeBuilder.CreateType()

        #Enum WTS_TYPE_CLASS https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_type_class
        $WTS_TYPE_CLASS_TypeBuilder = $ModuleBuilder.DefineEnum("$ModuleName.WTS_TYPE_CLASS", 'Public', [UInt16])
        $null = $WTS_TYPE_CLASS_TypeBuilder.DefineLiteral('WTSTypeProcessInfoLevel0', [UInt16] 0)
        $null = $WTS_TYPE_CLASS_TypeBuilder.DefineLiteral('WTSTypeProcessInfoLevel1', [UInt16] 1)
        $null = $WTS_TYPE_CLASS_TypeBuilder.DefineLiteral('WTSTypeSessionInfoLevel1', [UInt16] 2)
        $null = $WTS_TYPE_CLASS_TypeBuilder.CreateType()

        #Struct WKSTA_USER_INFO_1 https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/ns-lmwksta-wksta_user_info_1
        $WKSTA_USER_INFO_1_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.WKSTA_USER_INFO_1", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $WKSTA_USER_INFO_1_TypeBuilder.DefineField('wkui1_username', [System.IntPtr], 'Public')
        $null = $WKSTA_USER_INFO_1_TypeBuilder.DefineField('wkui1_logon_domain', [System.IntPtr], 'Public')
        $null = $WKSTA_USER_INFO_1_TypeBuilder.DefineField('wkui1_oth_domains', [System.IntPtr], 'Public')
        $null = $WKSTA_USER_INFO_1_TypeBuilder.DefineField('wkui1_logon_server', [System.IntPtr], 'Public')
        $null = $WKSTA_USER_INFO_1_TypeBuilder.CreateType()

        #Struct SESSION_INFO_2 https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-session_info_2
        $SESSION_INFO_2_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.SESSION_INFO_2", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $SESSION_INFO_2_TypeBuilder.DefineField('sesi2_cname', [System.IntPtr], 'Public')
        $null = $SESSION_INFO_2_TypeBuilder.DefineField('sesi2_username', [System.IntPtr], 'Public')
        $null = $SESSION_INFO_2_TypeBuilder.DefineField('sesi2_num_opens', [UInt32], 'Public')
        $null = $SESSION_INFO_2_TypeBuilder.DefineField('sesi2_time', [UInt32], 'Public')
        $null = $SESSION_INFO_2_TypeBuilder.DefineField('sesi2_idle_time', [UInt32], 'Public')
        $null = $SESSION_INFO_2_TypeBuilder.DefineField('sesi2_user_flags', [UInt32], 'Public')
        $null = $SESSION_INFO_2_TypeBuilder.DefineField('sesi2_cltype_name', [System.IntPtr], 'Public')
        $null = $SESSION_INFO_2_TypeBuilder.CreateType()

        #Struct WTS_SESSION_INFO_1W https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wts_session_info_1w
        $WTS_SESSION_INFO_1W_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.WTS_SESSION_INFO_1W", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.DefineField('ExecEnvId', [Uint32], 'Public')
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.DefineField('State', [VSEM.WTS_CONNECTSTATE_CLASS], 'Public')
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.DefineField('SessionId', [Uint32], 'Public')
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.DefineField('pSessionName', [System.IntPtr], 'Public')
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.DefineField('pHostName', [System.IntPtr], 'Public')
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.DefineField('pUserName', [System.IntPtr], 'Public')
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.DefineField('pDomainName', [System.IntPtr], 'Public')
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.DefineField('pFarmName', [System.IntPtr], 'Public')
        $null = $WTS_SESSION_INFO_1W_TypeBuilder.CreateType()

        #Struct LUID https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid
        $LUID_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.LUID", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $LUID_TypeBuilder.DefineField('LowPart', [UInt32], 'Public')
        $null = $LUID_TypeBuilder.DefineField('HighPart', [Int32], 'Public')
        $null = $LUID_TypeBuilder.CreateType()

        #Struct LSA_UNICODE_STRING https://learn.microsoft.com/en-us/windows/win32/api/lsalookup/ns-lsalookup-lsa_unicode_string
        $LSA_UNICODE_STRING_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.LSA_UNICODE_STRING", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $LSA_UNICODE_STRING_TypeBuilder.DefineField('Length', [UInt16], 'Public')
        $null = $LSA_UNICODE_STRING_TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public')
        $null = $LSA_UNICODE_STRING_TypeBuilder.DefineField('Buffer', [IntPtr], 'Public')
        $null = $LSA_UNICODE_STRING_TypeBuilder.CreateType()

        #Struct LSA_LAST_INTER_LOGON_INFO https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-lsa_last_inter_logon_info
        $LSA_LAST_INTER_LOGON_INFO_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.LSA_LAST_INTER_LOGON_INFO", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $LSA_LAST_INTER_LOGON_INFO_TypeBuilder.DefineField('LastSuccessfulLogon', [Int64], 'Public')
        $null = $LSA_LAST_INTER_LOGON_INFO_TypeBuilder.DefineField('LastFailedLogon', [Int64], 'Public')
        $null = $LSA_LAST_INTER_LOGON_INFO_TypeBuilder.DefineField('FailedAttemptCountSinceLastSuccessfulLogon', [UInt64], 'Public')
        $null = $LSA_LAST_INTER_LOGON_INFO_TypeBuilder.CreateType()

        #Struct SECURITY_LOGON_SESSION_DATA https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-security_logon_session_data
        $SECURITY_LOGON_SESSION_DATA_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.SECURITY_LOGON_SESSION_DATA", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('Size', [UInt32], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('LogonId', [VSEM.LUID], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('Username', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('LogonDomain', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('AuthenticationPackage', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('LogonType', [UInt32], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('Session', [UInt32], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('PSiD', [IntPtr], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('LogonTime', [UInt64], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('LogonServer', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('DnsDomainName', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('Upn', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('UserFlags', $(If ([Environment]::Is64BitProcess) {[UInt64]} Else {[UInt32]}), 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('LastLogonInfo', [VSEM.LSA_LAST_INTER_LOGON_INFO], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('LogonScript', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('ProfilePath', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('HomeDirectory', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('HomeDirectoryDrive', [VSEM.LSA_UNICODE_STRING], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('LogoffTime', [Int64], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('KickOffTime', [Int64], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('PasswordLastSet', [Int64], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('PasswordCanChange', [Int64], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.DefineField('PasswordMustChange', [Int64], 'Public')
        $null = $SECURITY_LOGON_SESSION_DATA_TypeBuilder.CreateType()

        #Struct SID https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
        #$SID_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.SID", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], 12)

        #Netapi32.dll
        $Netapi32_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.Netapi32", 'Public,BeforeFieldInit')

        #Function NetWkstaUserEnum https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum
        $NetWkstaUserEnum_method = $Netapi32_TypeBuilder.DefineMethod(
            'NetWkstaUserEnum',
            'Public,Static,PinvokeImpl',
            [Int32],
            @(
                [String], # _In_ LPWSTR servername
                [UInt32], # _In_ DWORD level
                [IntPtr].MakeByRefType(), # _Out_ LPBYTE *bufptr
                [UInt32], # _In_ DWORD prefmaxlen
                [UInt32].MakeByRefType(), # _Out_ LPDWORD entriesread
                [UInt32].MakeByRefType(), # _Out_ LPDWORD totalentries
                [UInt32].MakeByRefType()     # _Inout_ LPDWORD resumehandle
            )
        )
        
        #Function NetSessionEnum https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum
        $NetSessionEnum_method = $Netapi32_TypeBuilder.DefineMethod(
            'NetSessionEnum',
            'Public,Static,PinvokeImpl',
            [Int32],
            @(
                [String], # _In_ LMSTR   servername
                [String], # _In_ LMSTR   UncClientName
                [String], # _In_ LMSTR   username
                [UInt32], # _In_ DWORD level
                [IntPtr].MakeByRefType(), # _Out_ LPBYTE *bufptr
                [UInt32], # _In_ DWORD prefmaxlen
                [UInt32].MakeByRefType(), # _Out_ LPDWORD entriesread
                [UInt32].MakeByRefType(), # _Out_ LPDWORD totalentries
                [UInt32].MakeByRefType()     # _Inout_ LPDWORD resumehandle
            )
        )

        #Function NetApiBufferFree https://learn.microsoft.com/en-us/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree
        $NetApiBufferFree_method = $Netapi32_TypeBuilder.DefineMethod(
            'NetApiBufferFree',
            'Public,Static,PinvokeImpl',
            [Int32],
            @(
                [IntPtr]    # _In_ LPVOID Buffer
            )
        )

        #wtsapi32.dll
        $wtsapi32_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.wtsapi32", 'Public,BeforeFieldInit')

        #Function WTSEnumerateSessionsExW https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsexw
        $WTSEnumerateSessionsExW_method = $wtsapi32_TypeBuilder.DefineMethod(
            'WTSEnumerateSessionsExW',
            'Public,Static,PinvokeImpl',
            [bool],
            @(
                [IntPtr], # _In_ HANDLE hServer
                [UInt32].MakeByRefType(), # _Inout_ DWORD *pLevel
                [UInt32], # _In_ DWORD Filter
                [IntPtr].MakeByRefType(), # _Out_ PWTS_SESSION_INFO_1 *ppSessionInfo
                [UInt32].MakeByRefType()     # _Out_ DWORD *pCount
            )
        )

        #Function WTSLogoffSession https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtslogoffsession
        $WTSLogoffSession_method = $wtsapi32_TypeBuilder.DefineMethod(
            'WTSLogoffSession',
            'Public,Static,PinvokeImpl',
            [bool],
            @(
                [IntPtr], # _In_ HANDLE hServer
                [UInt32], # _In_ DWORD SessionId
                [bool] # _In_ BOOL bWait
            )
        )

        #Function WTSFreeMemoryExW https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsfreememoryexw
        $WTSFreeMemoryExW_method = $wtsapi32_TypeBuilder.DefineMethod(
            'WTSFreeMemoryExW',
            'Public,Static,PinvokeImpl',
            [bool],
            @(
                [VSEM.WTS_TYPE_CLASS], # _In_ WTS_TYPE_CLASS WTSTypeClass
                [IntPtr], # _In_ PVOID pMemory
                [UInt32] # _In_ ULONG NumberOfEntries
            )
        )

        #Secur32.dll
        $Secur32_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.Secur32", 'Public,BeforeFieldInit')

        #Function LsaEnumerateLogonSessions https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumeratelogonsessions
        $LsaEnumerateLogonSessions_method = $Secur32_TypeBuilder.DefineMethod(
            'LsaEnumerateLogonSessions',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [UInt64].MakeByRefType(), # _Out_ PULONG LogonSessionCount
                [IntPtr].MakeByRefType() # _Out_ PLUID  *LogonSessionList
            )
        )

        #Function LsaGetLogonSessionData https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsagetlogonsessiondata
        $LsaGetLogonSessionData_method = $Secur32_TypeBuilder.DefineMethod(
            'LsaGetLogonSessionData',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr], #_In_ PLUID LogonId,
                [IntPtr].MakeByRefType() #_Out_ PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData
            )
        )

        #Function LsaFreeReturnBuffer https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsafreereturnbuffer
        $LsaFreeReturnBuffer_method = $Secur32_TypeBuilder.DefineMethod(
            'LsaFreeReturnBuffer',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr] #_In_ PVOID Buffer
            )
        )

        #Build attributes
        @('Netapi32', $NetWkstaUserEnum_method), `
        @('Netapi32', $NetSessionEnum_method), `
        @('Netapi32', $NetApiBufferFree_method), `
        @('wtsapi32', $WTSEnumerateSessionsExW_method), `
        @('wtsapi32', $WTSLogoffSession_method), `
        @('wtsapi32', $WTSFreeMemoryExW_method), `
        @('Secur32', $LsaEnumerateLogonSessions_method), `
        @('Secur32', $LsaGetLogonSessionData_method), `
        @('Secur32', $LsaFreeReturnBuffer_method) | ForEach-Object {
            $DllImportAttribute = [Reflection.Emit.CustomAttributeBuilder]::New(
                $Constructor,
                $_[0], 
                [Reflection.PropertyInfo[]] @(), 
                [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField, $EntryPointField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention]::StdCall), ([Runtime.InteropServices.CharSet]::Unicode), $_[1].Name)
            )
            $_[1].SetCustomAttribute($DllImportAttribute)
        }

        #Create types
        $null = $Netapi32_TypeBuilder.CreateType()
        $null = $wtsapi32_TypeBuilder.CreateType()
        $null = $Secur32_TypeBuilder.CreateType()

        #Success
        Return [UInt32]'0x0'
    }
    Catch {
        #Failed
        Return [UInt32]'0xffffffff'
    }
}

#Returns list of Logged On Users via NetWkstaUserEnum API. 
Function Get-VSEMWkstaLoggedOnUsers {
    [CmdletBinding()]
    Param()

    If ((Import-VSEModule) -ne 0) {
        Write-Error -Message 'Unable to create in-memory module. Please, rerun this cmdlet in new powershell process (version 5.1/7.0 or above)'
        Return
    }
    $Buffer = [intptr]::Zero
    $entriesread = 0
    $totalentries = 0
    $UserInfos = [System.Collections.Generic.List[PSCustomObject]]::New()
    $Result = [VSEM.Netapi32]::NetWkstaUserEnum($null, 1, [ref]$Buffer, [UInt32]'0xffffffff', [ref]$entriesread, [ref]$totalentries, [ref]$null)
    For ($i = 0; $i -lt $entriesread; $i++) {
        #$WKSTA_USER_INFO_1 = [Runtime.InteropServices.Marshal]::PtrToStructure[VSEM.WKSTA_USER_INFO_1]($Buffer + [int64]($i * 32))
        $WKSTA_USER_INFO_1 = [Runtime.InteropServices.Marshal]::PtrToStructure([intptr]::Add($Buffer, ($i * [Runtime.InteropServices.Marshal]::SizeOf([System.Type][VSEM.WKSTA_USER_INFO_1]))), [System.Type][VSEM.WKSTA_USER_INFO_1])
        $UserInfo1 = [PSCustomObject]@{
            UserName     = [Runtime.InteropServices.Marshal]::PtrToStringUni($WKSTA_USER_INFO_1.wkui1_username)
            UserDomain   = [Runtime.InteropServices.Marshal]::PtrToStringUni($WKSTA_USER_INFO_1.wkui1_logon_domain)
            OtherDomains = [Runtime.InteropServices.Marshal]::PtrToStringUni($WKSTA_USER_INFO_1.wkui1_oth_domains)
            LogonServer  = [Runtime.InteropServices.Marshal]::PtrToStringUni($WKSTA_USER_INFO_1.wkui1_logon_server)
        }
        $UserInfos.Add($UserInfo1)
    }
    $null = [VSEM.Netapi32]::NetApiBufferFree($Buffer)
    Return $UserInfos
}

#Returns list of sessions of Logged On Users by network via NetSessionEnum API. 
Function Get-VSEMNetSessions {
    [CmdletBinding()]
    Param()

    If ((Import-VSEModule) -ne 0) {
        Write-Error -Message 'Unable to create in-memory module. Please, rerun this cmdlet in new powershell process (version 5.1/7.0 or above)'
        Return
    }
    $Buffer = [intptr]::Zero
    $entriesread = 0
    $totalentries = 0
    $Sessions = [System.Collections.Generic.List[PSCustomObject]]::New()
    $Result = [VSEM.Netapi32]::NetSessionEnum($null, $null, $null, 2, [ref]$Buffer, [UInt32]'0xffffffff', [ref]$entriesread, [ref]$totalentries, [ref]$null)
    For ($i = 0; $i -lt $entriesread; $i++) {
        #$SESSION_INFO_2 = [Runtime.InteropServices.Marshal]::PtrToStructure[VSEM.SESSION_INFO_2]($Buffer + [int64]($i * 40))
        $SESSION_INFO_2 = [Runtime.InteropServices.Marshal]::PtrToStructure([intptr]::Add($Buffer, ($i * [Runtime.InteropServices.Marshal]::SizeOf([System.Type][VSEM.SESSION_INFO_2]))), [System.Type][VSEM.SESSION_INFO_2])
        $Session2 = [PSCustomObject]@{
            ComputerName   = [Runtime.InteropServices.Marshal]::PtrToStringUni($SESSION_INFO_2.sesi2_cname)
            UserName       = [Runtime.InteropServices.Marshal]::PtrToStringUni($SESSION_INFO_2.sesi2_username)
            NumOpens       = $SESSION_INFO_2.sesi2_num_opens
            Time           = $SESSION_INFO_2.sesi2_time
            IdleTime       = $SESSION_INFO_2.sesi2_idle_time
            UserFlags      = $SESSION_INFO_2.sesi2_user_flags
            ConnectionType = [Runtime.InteropServices.Marshal]::PtrToStringUni($SESSION_INFO_2.sesi2_cltype_name)
        }
        $Sessions.Add($Session2)
    }
    $null = [VSEM.Netapi32]::NetApiBufferFree($Buffer)
    Return $Sessions
}

#Returns list of terminal sessions of Logged On Users via WTSEnumerateSessionsExW API. 
Function Get-VSEMTSSessions {
    [CmdletBinding()]
    Param()

    If ((Import-VSEModule) -ne 0) {
        Write-Error -Message 'Unable to create in-memory module. Please, rerun this cmdlet in new powershell process (version 5.1/7.0 or above)'
        Return
    }
    $Buffer = [intptr]::Zero
    $Count = 0
    $Sessions = [System.Collections.Generic.List[PSCustomObject]]::New()
    $Result = [VSEM.wtsapi32]::WTSEnumerateSessionsExW([IntPtr]::Zero, [ref]1, 0, [ref]$Buffer, [ref]$Count)
    For ($i = 0; $i -lt $Count; $i++) {
        #$WTS_SESSION_INFO_1W = [Runtime.InteropServices.Marshal]::PtrToStructure[VSEM.WTS_SESSION_INFO_1W]($Buffer + [int64]($i * 56))
        $WTS_SESSION_INFO_1W = [Runtime.InteropServices.Marshal]::PtrToStructure([intptr]::Add($Buffer, ($i * [Runtime.InteropServices.Marshal]::SizeOf([System.Type][VSEM.WTS_SESSION_INFO_1W]))), [System.Type][VSEM.WTS_SESSION_INFO_1W])
        $Session1W = [PSCustomObject]@{
            ExecEnvId   = $WTS_SESSION_INFO_1W.ExecEnvId
            State       = $WTS_SESSION_INFO_1W.State
            SessionId   = $WTS_SESSION_INFO_1W.SessionId
            SessionName = [Runtime.InteropServices.Marshal]::PtrToStringUni($WTS_SESSION_INFO_1W.pSessionName)
            HostName    = [Runtime.InteropServices.Marshal]::PtrToStringUni($WTS_SESSION_INFO_1W.pHostName)
            UserName    = [Runtime.InteropServices.Marshal]::PtrToStringUni($WTS_SESSION_INFO_1W.pUserName)
            DomainName  = [Runtime.InteropServices.Marshal]::PtrToStringUni($WTS_SESSION_INFO_1W.pDomainName)
            FarmName    = [Runtime.InteropServices.Marshal]::PtrToStringUni($WTS_SESSION_INFO_1W.pFarmName)
        }
        $Sessions.Add($Session1W)
    }
    $null = [VSEM.wtsapi32]::WTSFreeMemoryExW([VSEM.WTS_TYPE_CLASS]::WTSTypeSessionInfoLevel1, $Buffer, $Count)
    Return $Sessions
}

#TODO: Function WTSQuerySessionInformationW https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw

#Logoffs user by SessionId. SessionId may be obtained by Get-VSEMTSSessions OR Get-VSEMSecSessions.
# Requires run as admin
Function Invoke-VSEMTSLogoffSession {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [UInt32]$SessionId,
        [Switch]$Wait # Indicates whether the operation is synchronous.If Wait is specified, the function returns when the session is logged off. If Wait is ommited, the function returns immediately.
    )

    If ((Import-VSEModule) -ne 0) {
        Write-Error -Message 'Unable to create in-memory module. Please, rerun this cmdlet in new powershell process (version 5.1/7.0 or above)'
        Return
    }
    If ($Wait) {
        Return [VSEM.wtsapi32]::WTSLogoffSession([IntPtr]::Zero, $SessionId, $true)
    }
    Else {
        Return [VSEM.wtsapi32]::WTSLogoffSession([IntPtr]::Zero, $SessionId, $false)
    }
}

#Returns list of security sessions of Logged On Users via LsaEnumerateLogonSessions and LsaGetLogonSessionData API. 
#Run as admin to get more data
Function Get-VSEMSecSessions {
    [CmdletBinding()]
    Param()

    If ((Import-VSEModule) -ne 0) {
        Write-Error -Message 'Unable to create in-memory module. Please, rerun this cmdlet in new powershell process (version 5.1/7.0 or above)'
        Return
    }

    $LogonSessionCount = [UInt64]0
    $LogonSessionList = [IntPtr]::Zero
    $Sessions = [System.Collections.Generic.List[PSCustomObject]]::New()
    $Result = [VSEM.Secur32]::LsaEnumerateLogonSessions([ref]$LogonSessionCount, [ref]$LogonSessionList)
    For ($i = 0; $i -lt $LogonSessionCount; $i++) {
        $ppLogonSessionData = [IntPtr]::Zero
        $ResultData = [VSEM.Secur32]::LsaGetLogonSessionData([intptr]::Add($LogonSessionList, ($i * [Runtime.InteropServices.Marshal]::SizeOf([System.Type][IntPtr]))), [ref]$ppLogonSessionData)
        If ($ResultData -eq 0) {
            $LogonSessionData = [Runtime.InteropServices.Marshal]::PtrToStructure($ppLogonSessionData, [System.Type][VSEM.SECURITY_LOGON_SESSION_DATA])
            $SECURITY_LOGON_SESSION_DATA = [PSCustomObject]@{
                Size                                       = $LogonSessionData.Size
                LogonId                                    = @{LowPart = $LogonSessionData.LogonId.LowPart; HighPart = $LogonSessionData.LogonId.HighPart }
                Username                                   = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.Username.Buffer,$LogonSessionData.Username.Length/2)
                LogonDomain                                = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.LogonDomain.Buffer,$LogonSessionData.LogonDomain.Length/2)
                AuthenticationPackage                      = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.AuthenticationPackage.Buffer,$LogonSessionData.AuthenticationPackage.Length/2)
                LogonType                                  = $LogonSessionData.LogonType
                SessionId                                  = $LogonSessionData.Session
                SID                                        = Try { [System.Security.Principal.SecurityIdentifier]::New($LogonSessionData.PSiD) }Catch {};
                LogonTime                                  = [datetime]::FromFileTime([Math]::Min(2650467635999999999, $LogonSessionData.LogonTime))
                LogonServer                                = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.LogonServer.Buffer,$LogonSessionData.LogonServer.Length/2)
                DnsDomainName                              = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.DnsDomainName.Buffer,$LogonSessionData.DnsDomainName.Length/2)
                Upn                                        = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.Upn.Buffer,$LogonSessionData.Upn.Length/2)
                UserFlags                                  = $LogonSessionData.UserFlags
                LastSuccessfulLogon                        = [datetime]::FromFileTime([Math]::Min(2650467635999999999, $LogonSessionData.LastLogonInfo.LastSuccessfulLogon))
                LastFailedLogon                            = [datetime]::FromFileTime([Math]::Min(2650467635999999999, $LogonSessionData.LastLogonInfo.LastFailedLogon))
                FailedAttemptCountSinceLastSuccessfulLogon = $LogonSessionData.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon
                LogonScript                                = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.LogonScript.Buffer,$LogonSessionData.LogonScript.Length/2)
                ProfilePath                                = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.ProfilePath.Buffer,$LogonSessionData.ProfilePath.Length/2)
                HomeDirectory                              = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.HomeDirectory.Buffer,$LogonSessionData.HomeDirectory.Length/2)
                HomeDirectoryDrive                         = [Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.HomeDirectoryDrive.Buffer,$LogonSessionData.HomeDirectoryDrive.Length/2)
                LogoffTime                                 = [datetime]::FromFileTime([Math]::Min(2650467635999999999, $LogonSessionData.LogoffTime))
                KickOffTime                                = [datetime]::FromFileTime([Math]::Min(2650467635999999999, $LogonSessionData.KickOffTime))
                PasswordLastSet                            = [datetime]::FromFileTime([Math]::Min(2650467635999999999, $LogonSessionData.PasswordLastSet))
                PasswordCanChange                          = [datetime]::FromFileTime([Math]::Min(2650467635999999999, $LogonSessionData.PasswordCanChange))
                PasswordMustChange                         = [datetime]::FromFileTime([Math]::Min(2650467635999999999, $LogonSessionData.PasswordMustChange))
            }
            $Sessions.Add($SECURITY_LOGON_SESSION_DATA)
            $null = [VSEM.Secur32]::LsaFreeReturnBuffer($ppLogonSessionData)
        }
    }
    $null = [VSEM.Secur32]::LsaFreeReturnBuffer($LogonSessionList)
    Return $Sessions
}