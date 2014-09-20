#include "hasher.hpp"



hasher::hasher(std::string str)
:source(str)
{

    SHA1();
    SHA224();
    SHA256();
    SHA384();
    SHA512();
    SHA3_224();
    SHA3_256();
    SHA3_384();
    SHA3_512();
    Tiger();
    WHIRLPOOL();
    RIPEMD128();
    RIPEMD256();
    RIPEMD160();
    RIPEMD320();
    MD2();
    MD4();
    MD5();
}

hasher::~hasher()
{
    
}

void hasher::SHA1()
{
	CryptoPP::SHA1 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA1_str))));
}

void hasher::SHA224()
{
	CryptoPP::SHA224 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA224_str))));
}

void hasher::SHA256()
{
	CryptoPP::SHA256 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA256_str))));
}

void hasher::SHA384()
{
	CryptoPP::SHA384 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA384_str))));
}

void hasher::SHA512()
{
	CryptoPP::SHA512 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA512_str))));
}

void hasher::SHA3_224()
{
	CryptoPP::SHA3_224 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA3_224_str))));
}

void hasher::SHA3_256()
{
	CryptoPP::SHA3_256 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA3_256_str))));
}

void hasher::SHA3_384()
{
	CryptoPP::SHA3_384 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA3_384_str))));
}

void hasher::SHA3_512()
{
	CryptoPP::SHA3_512 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(SHA3_512_str))));
}

void hasher::Tiger()
{
	CryptoPP::Tiger hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(Tiger_str))));
}

void hasher::WHIRLPOOL()
{
	CryptoPP::Whirlpool hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(WHIRLPOOL_str))));
}

void hasher::RIPEMD128()
{
	CryptoPP::RIPEMD128 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(RIPEMD128_str))));
}

void hasher::RIPEMD256()
{
	CryptoPP::RIPEMD256 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(RIPEMD256_str))));
}

void hasher::RIPEMD160()
{
	CryptoPP::RIPEMD160 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(RIPEMD160_str))));
}

void hasher::RIPEMD320()
{
	CryptoPP::RIPEMD320 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(RIPEMD320_str))));
}

void hasher::MD2()
{
	CryptoPP::MD2 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(MD2_str))));
}

void hasher::MD4()
{
	CryptoPP::MD4 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(MD4_str))));
}

void hasher::MD5()
{
	CryptoPP::MD5 hash;
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(MD5_str))));
}
std::string hasher::get_SHA1()
	{
		return SHA1_str;
	}

	std::string hasher::get_SHA224()
	{
		return SHA224_str;
	}

	std::string hasher::get_SHA256()
	{
		return SHA256_str;
	}

	std::string hasher::get_SHA384()
	{
		return SHA384_str;
	}

	std::string hasher::get_SHA512()
	{
		return SHA512_str;
	}

	std::string hasher::get_SHA3_224()
	{
		return SHA3_224_str;
	}

	std::string hasher::get_SHA3_256()
	{
		return SHA3_256_str;
	}

	std::string hasher::get_SHA3_384()
	{
		return SHA3_384_str;
	}

	std::string hasher::get_SHA3_512()
	{
		return SHA3_512_str;
	}

	std::string hasher::get_Tiger()
	{
		return Tiger_str;
	}

	std::string hasher::get_WHIRLPOOL()
	{
		return WHIRLPOOL_str;
	}

	std::string hasher::get_RIPEMD128()
	{
		return RIPEMD128_str;
	}

	std::string hasher::get_RIPEMD256()
	{
		return RIPEMD256_str;
	}

	std::string hasher::get_RIPEMD160()
	{
		return RIPEMD160_str;
	}

	std::string hasher::get_RIPEMD320()
	{
		return RIPEMD320_str;
	}

	std::string hasher::get_MD2()
	{
		return MD2_str;
	}

	std::string hasher::get_MD4()
	{
		return MD4_str;
	}

	std::string hasher::get_MD5()
	{
		return MD5_str;
	}

boost::property_tree::ptree hasher::xml_node()
{
    using boost::property_tree::ptree;
    
    boost::property_tree::ptree keynode;
    keynode.put("<xmlattr>.value", source);
    
    std::array<const char*, 18> algorithms = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512", "TIGER", "WHIRLPOOL", "RIPEMD128", "RIPEMD256", "RIPEMD160", "RIPEMD320", "MD2", "MD4", "MD5"};
    
    std::array<std::string, 18> hashes = {SHA1_str, SHA224_str, SHA256_str, SHA384_str, SHA512_str, SHA3_224_str, SHA3_256_str, SHA3_384_str, SHA3_512_str, Tiger_str, WHIRLPOOL_str, RIPEMD128_str, RIPEMD256_str, RIPEMD160_str, RIPEMD320_str, MD2_str, MD4_str, MD5_str};
    
    std::array<const char*, 18>::const_iterator ait;
    std::array<std::string, 18>::const_iterator hit;
    
    for (ait=algorithms.begin(), hit=hashes.begin(); ait != algorithms.end() && hit != hashes.end(); ait++, hit++)
    {

        keynode.put(*ait,*hit);
        
    }
    
    return keynode;
}