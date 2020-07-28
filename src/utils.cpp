#include "utils.h"

#include <sodium/randombytes.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include <iostream>
#include <fstream>

static void stdin_echo(bool enable)
{
#if defined(_WIN32)
	auto hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode;
	GetConsoleMode(hStdin, &mode);

	if (!enable)
	{
		mode &= ~ENABLE_ECHO_INPUT;
	}
	else
	{
		mode |= ENABLE_ECHO_INPUT;
	}

	SetConsoleMode(hStdin, mode);
#else
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	if (!enable)
		tty.c_lflag &= ~ECHO;
	else
		tty.c_lflag |= ECHO;

	(void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

std::string request_password_input()
{
	std::cout << "Password: ";
	stdin_echo(false);

	std::string pass;
	std::getline(std::cin, pass);

	stdin_echo(true);

	std::cout << std::endl;

	return std::move(pass);
}

std::string get_file_path_without_ext(std::string file)
{
	size_t file_name_index = file.find_last_of("/\\");

	if (file_name_index == std::string::npos) // No path provided
	{
		size_t ext_index = file.find_first_of(".");

		if (ext_index == std::string::npos) // No extension
		{
			return file;
		}
		else
		{
			return file.substr(0, ext_index);
		}
	}
	else
	{
		std::string file_name = file.substr(file_name_index + 1);

		size_t ext_index = file_name.find_first_of(".");

		if (ext_index == std::string::npos)
		{
			return file;
		}
		else
		{
			return file.substr(0, file_name_index + ext_index + 1);
		}
	}
}

std::string get_file_name(std::string file_path)
{
	size_t file_name_index = file_path.find_last_of("/\\");

	if (file_name_index == std::string::npos) // No path provided
	{
		return file_path;
	}
	else
	{
		return file_path.substr(file_name_index + 1);
	}
}

std::string get_path(std::string file_path)
{
	size_t file_name_index = file_path.find_last_of("/\\");

	if (file_name_index == std::string::npos)
	{
		return {};
	}
	else
	{
		return file_path.substr(0, file_name_index + 1);
	}
}

void shred_file(const std::string& file_path)
{
	std::ofstream shredder(file_path, std::ios::binary);
	std::streampos shredded = 0;

	shredder.seekp(0, std::ios::end);
	auto size = shredder.tellp();
	shredder.seekp(0);

	unsigned char random_data[64];

	while (shredded < size)
	{
		randombytes_buf(random_data, sizeof(random_data));
		shredder.write((char*)random_data, sizeof(random_data));
		shredded += sizeof(random_data);
	}

	shredder.flush();
}
