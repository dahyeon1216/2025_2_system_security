#include <stdio.h>
#include <Windows.h>
int main(void)
{
	HMODULE h = LoadLibraryA("DLL.dll");
	if (h == NULL)
		return GetLastError();
	int (*add)(int, int) = (int (*)(int, int))GetProcAddress(h, "add");
	printf("hello world %d\n", add(10, 3));
	FreeLibrary(h);
	return 0;
}






