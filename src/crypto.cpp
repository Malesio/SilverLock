#include "crypto.h"
#include "utils.h"

#include <sodium.h>

#include <fstream>
#include <iostream>
#include <tuple>
#include <array>
#include <cstring>

auto derive_key_from_password(const std::string& pass)
{
	std::array<unsigned char, crypto_pwhash_SALTBYTES> salt;
	std::array<unsigned char, crypto_secretstream_xchacha20poly1305_KEYBYTES> key;

	randombytes_buf(salt.data(), salt.size());

	crypto_pwhash(key.data(), key.size(),
		pass.c_str(), pass.size(),
		salt.data(),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE,
		crypto_pwhash_ALG_DEFAULT);

	return std::make_tuple(std::move(key), std::move(salt));
}

auto derive_key_from_password(const std::string& pass, const std::array<unsigned char, crypto_pwhash_SALTBYTES>& salt)
{
	std::array<unsigned char, crypto_secretstream_xchacha20poly1305_KEYBYTES> key;

	crypto_pwhash(key.data(), key.size(),
		pass.c_str(), pass.size(),
		salt.data(),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE,
		crypto_pwhash_ALG_DEFAULT);

	return std::move(key);
}

static decrypt_result decrypt_file(std::ifstream& is, const std::string& file_path, const std::string& password, bool keep_original)
{
	crypto_secretstream_xchacha20poly1305_state crypto_state;
	crypto_generichash_state hash_state;

	std::array<unsigned char, crypto_secretstream_xchacha20poly1305_KEYBYTES> key;
	std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES> crypto_header;
	std::array<unsigned char, 4096 + crypto_secretstream_xchacha20poly1305_ABYTES> buf_in;
	std::array<unsigned char, 4096> buf_out;
	std::array<unsigned char, crypto_generichash_BYTES> file_mac;
	std::array<unsigned char, crypto_generichash_BYTES> computed_mac;
	std::array<unsigned char, crypto_pwhash_SALTBYTES> file_salt;
	std::vector<unsigned char> obf_original_file_name;
	std::string original_file_name;
	uint32_t original_file_name_len;
	bool eof{ false };
	unsigned char tag;
	unsigned long long out_len;

	is.read((char*)file_mac.data(), file_mac.size());
	is.read((char*)file_salt.data(), file_salt.size());
	is.read((char*)&original_file_name_len, sizeof(original_file_name_len));

	obf_original_file_name.resize(original_file_name_len);

	is.read((char*)obf_original_file_name.data(), original_file_name_len);

	key = derive_key_from_password(password, file_salt);

	crypto_generichash_init(&hash_state, key.data(), key.size(), computed_mac.size());
	
	crypto_generichash_update(&hash_state, file_salt.data(), file_salt.size());
	crypto_generichash_update(&hash_state, (const unsigned char*)&original_file_name_len, sizeof(uint32_t));
	crypto_generichash_update(&hash_state, (const unsigned char*)obf_original_file_name.data(), obf_original_file_name.size());

	crypto_generichash_final(&hash_state, computed_mac.data(), computed_mac.size());

	if (sodium_memcmp(file_mac.data(), computed_mac.data(), file_mac.size()) != 0)
	{
		return decrypt_result::bad_header;
	}

	original_file_name = clear_things_up(obf_original_file_name, file_salt);

	std::ofstream output_file(get_path(file_path) + original_file_name, std::ios::binary);

	is.read((char*)crypto_header.data(), crypto_header.size());

	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state, crypto_header.data(), key.data()) != 0)
	{
		return decrypt_result::bad_data;
	}

	while (!eof)
	{
		is.read((char*)buf_in.data(), buf_in.size());
		size_t rlen = is.gcount();
		eof = is.eof();

		if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, buf_out.data(), &out_len, &tag, buf_in.data(), rlen, nullptr, 0) != 0)
		{
			return decrypt_result::bad_data;
		}

		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof)
		{
			return decrypt_result::stream_truncated;
		}
		
		output_file.write((char*)buf_out.data(), out_len);
	}

	if (!keep_original)
	{
		is.close();
		shred_file(file_path);
		std::remove(file_path.c_str());
	}

	return decrypt_result::ok;
}

static void encrypt_file(std::ifstream& is, const std::string& file_path, const std::string& password, bool keep_original)
{
	auto key_and_salt = derive_key_from_password(password);

	auto& key = std::get<0>(key_and_salt);
	auto& salt = std::get<1>(key_and_salt);

	auto obf_file_name = jumble_things_up(get_file_name(file_path), salt);
	uint32_t file_name_len = obf_file_name.size();

	crypto_secretstream_xchacha20poly1305_state crypto_state;
	crypto_generichash_state hash_state;
	
	std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES> crypto_header;
	std::array<unsigned char, 4096> buf_in;
	std::array<unsigned char, 4096 + crypto_secretstream_xchacha20poly1305_ABYTES> buf_out;
	std::array<unsigned char, crypto_generichash_BYTES> mac;
	bool eof{ false };
	unsigned char tag;
	unsigned long long out_len;

	crypto_generichash_init(&hash_state, key.data(), key.size(), mac.size());

	crypto_generichash_update(&hash_state, salt.data(), salt.size());
	crypto_generichash_update(&hash_state, (const unsigned char*)&file_name_len, sizeof(uint32_t));
	crypto_generichash_update(&hash_state, obf_file_name.data(), obf_file_name.size());

	crypto_generichash_final(&hash_state, mac.data(), mac.size());

	std::ofstream output_file(get_file_path_without_ext(file_path) + ".agl", std::ios::binary);

	output_file.write("AGL1", 4);
	output_file.write((const char*)mac.data(), mac.size());
	output_file.write((const char*)salt.data(), salt.size());
	output_file.write((const char*)&file_name_len, sizeof(file_name_len));
	output_file.write((const char*)obf_file_name.data(), obf_file_name.size());

	crypto_secretstream_xchacha20poly1305_init_push(&crypto_state, crypto_header.data(), key.data());
	
	output_file.write((const char*)crypto_header.data(), crypto_header.size());

	while (!eof)
	{
		is.read((char*)buf_in.data(), buf_in.size());
		std::streamsize rlen = is.gcount();
		eof = is.eof();
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

		crypto_secretstream_xchacha20poly1305_push(&crypto_state, buf_out.data(), &out_len, buf_in.data(), rlen, nullptr, 0, tag);

		output_file.write((const char*)buf_out.data(), out_len);
	}

	if (!keep_original)
	{
		is.close();
		shred_file(file_path);
		std::remove(file_path.c_str());
	}
}

void process_files(const std::vector<std::string>& files, process_flags flags, bool keep_original)
{
	if (sodium_init() != 0)
	{
		std::cerr << "Crypto engine failed to initialise.\n";
		return;
	}

	std::string pass = request_password_input();

	for (const auto& file : files)
	{
		std::ifstream input_file(file, std::ios::binary);
		std::string file_name = get_file_name(file);

		if (!input_file)
		{
			std::cerr << "Couldn't open file " << file_name << ", skipping...\n";
		}
		else
		{
			char magic[4] = { 0 };
			input_file.read(magic, 4);

			if (std::memcmp(magic, "AGL1", 4) == 0)
			{
				if (flags == process_flags::force_encrypt)
				{
					std::cerr << "Warning: Reencrypting an already encrypted file is pointless. Skipping...\n";
					continue;
				}

				switch (decrypt_file(input_file, file, pass, keep_original))
				{
				case decrypt_result::ok:
					std::cout << "File " << file_name << " decrypted.\n";
					break;
				case decrypt_result::bad_header:
					std::cerr << "ERROR: bad header data in file " << file_name << ". Skipping...\n";
					break;
				case decrypt_result::bad_data:
					std::cerr << "ERROR: stream corrupted in file " << file_name << ". Skipping...\n";
					break;
				case decrypt_result::stream_truncated:
					std::cerr << "ERROR: reached unexpected end of stream in file " << file_name << ". Skipping...\n";
				}
			}
			else
			{
				if (flags == process_flags::force_decrypt)
				{
					std::cerr << "Warning: file '" << file_name << "' does not look like a SilverLock file. Skipping...\n";
					continue;
				}

				input_file.seekg(0);

				encrypt_file(input_file, file, pass, keep_original);
			}
		}
	}
}
