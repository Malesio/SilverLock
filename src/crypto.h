#pragma once

#include <string>
#include <vector>

enum class process_flags
{
	autodetect,
	force_encrypt,
	force_decrypt
};

enum class decrypt_result
{
	ok,
	bad_header,
	bad_data,
	stream_truncated
};

void process_files(const std::vector<std::string>& files, 
	process_flags flags = process_flags::autodetect,
	bool keep_original = false);
