// enc.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <string>
#include "xnc.h"
using namespace std;

int timeToGO()
{
	// enc file 
	// 加密文件
	string path("plain.zip");
	string newpath("Crypted.en");
	return encfile((char*)path.c_str(), (char*)newpath.c_str());
	
	// dec file
	// 解密文件

	//string decpath("Crypted.zip");
	//return decfile((char*)newpath.c_str(), (char*)decpath.c_str());
}

int main()
{
	std::cout << "Files enc or dec test.\n";
	return timeToGO();
}
