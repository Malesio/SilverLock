#pragma once

#include <string>
#include <vector>
#include <cstdio>

std::string request_password_input();
std::string get_file_path_without_ext(std::string file_path);
std::string get_file_name(std::string file_path);
std::string get_path(std::string file_path);

void shred_file(const std::string& file_path);

template<typename ContiguousContainer>
inline std::vector<unsigned char> jumble_things_up(const std::string& text, const ContiguousContainer& key)
{
	std::vector<unsigned char> res(text.size());

	for (int i = 0; i < text.size(); i++)
	{
		res[i] = (unsigned char)text[i] ^ (unsigned char)key[i % key.size()];
	}

	return std::move(res);
}

template<typename ContiguousContainer>
inline std::string clear_things_up(const std::vector<unsigned char>& jumbled, const ContiguousContainer& key)
{
	std::string res(jumbled.size() + 1, 0);

	for (int i = 0; i < jumbled.size(); i++)
	{
		res[i] = (char) (jumbled[i] ^ (unsigned char)key[i % key.size()]);
	}

	return std::move(res);
}
