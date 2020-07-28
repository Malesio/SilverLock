#include "crypto.h"

#include "CLI11.hpp"

int main(int argc, char *argv[])
{
	CLI::App app{"Barebones file protector."};

	std::vector<std::string> files;
	bool keep_original{ false };

	app.add_option("files", files, "The files to decrypt or encrypt.\n"
		"Action is determined by the file contents: if a provided file\nseems encrypted (i.e. begins with magic bytes AGL1),\nit will be decrypted, "
		"otherwise it will be encrypted.")->required();
	auto decrypt_opt = app.add_flag("-d,--decrypt", "Force decrypt all files.\nNOTE: SilverLock will skip invalid files.");
	auto encrypt_opt = app.add_flag("-e,--encrypt", "Force encrypt all files.\nNOTE: SilverLock will skip already encrypted files.")->excludes(decrypt_opt);
	app.add_flag("-k,--keep", keep_original, "Do not erase the original file.");

	CLI11_PARSE(app, argc, argv);

	process_flags pflags = process_flags::autodetect;

	if (*decrypt_opt)
	{
		pflags = process_flags::force_decrypt;
	}
	else if (*encrypt_opt)
	{
		pflags = process_flags::force_encrypt;
	}

	process_files(files, pflags, false);
}
