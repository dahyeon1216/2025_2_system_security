// systemSecurity_1.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.

#include <iostream>

int add(int a, int b)
{
	int result = 0;
	result = a + b;
	return result;
}

int main(void)
{
	int retval = 0;
	int a = 0x10;
	int b = 0x20;
	printf("Program Started\n");
	retval = add(a, b);
	printf("%d\n",retval);
	printf("Program Ended\n");
	return 0;
}