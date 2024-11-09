#pragma once
// used: [stl] uint64_t
#include <cstdint>
// used: [stl] endian
#include <bit>

#if Q_HAS_INCLUDE("q-tee/crt/crt.h")
// used: stringlength
#include <q-tee/crt/crt.h>
#else
// used: [crt] strlen
#include <cstring>
#endif

#define Q_HASH_MURMUR2_64

#ifndef Q_HASH_MURMUR2_64_MODULO
#define Q_HASH_MURMUR2_64_MODULO 0xC6A4A7935BD1E995
#endif

using MurMur264_t = std::uint64_t;

/*
 * 64-BIT MURMUR2 HASH ALGORITHM
 * @credits: Austin Appleby
 */
namespace MURMUR2_64
{
	namespace DETAIL
	{
		consteval std::uint64_t XorShr(const std::uint64_t ullValue, const std::uint64_t ullShift)
		{
			return ullValue ^ (ullValue >> ullShift);
		}

		consteval MurMur264_t ProcessBlock(const char* szSource, const std::size_t nLength, const MurMur264_t ullHash)
		{
			return
				nLength >= 8U ? ProcessBlock(szSource + 8U, nLength - 8U, (ullHash ^ XorShr((static_cast<std::uint64_t>(szSource[0]) | (static_cast<std::uint64_t>(szSource[1]) << 8ULL) | (static_cast<std::uint64_t>(szSource[2]) << 16ULL) | (static_cast<std::uint64_t>(szSource[3]) << 24ULL) | (static_cast<std::uint64_t>(szSource[4]) << 32ULL) | (static_cast<std::uint64_t>(szSource[5]) << 40ULL) | (static_cast<std::uint64_t>(szSource[6]) << 48ULL) | (static_cast<std::uint64_t>(szSource[7]) << 56ULL)) * Q_HASH_MURMUR2_64_MODULO, 47ULL) * Q_HASH_MURMUR2_64_MODULO) * Q_HASH_MURMUR2_64_MODULO) :
				nLength == 7U ? ProcessBlock(szSource, nLength - 1U, ullHash ^ (static_cast<std::uint64_t>(szSource[6]) << 48ULL)) :
				nLength == 6U ? ProcessBlock(szSource, nLength - 1U, ullHash ^ (static_cast<std::uint64_t>(szSource[5]) << 40ULL)) :
				nLength == 5U ? ProcessBlock(szSource, nLength - 1U, ullHash ^ (static_cast<std::uint64_t>(szSource[4]) << 32ULL)) :
				nLength == 4U ? ProcessBlock(szSource, nLength - 1U, ullHash ^ (static_cast<std::uint64_t>(szSource[3]) << 24ULL)) :
				nLength == 3U ? ProcessBlock(szSource, nLength - 1U, ullHash ^ (static_cast<std::uint64_t>(szSource[2]) << 16ULL)) :
				nLength == 2U ? ProcessBlock(szSource, nLength - 1U, ullHash ^ (static_cast<std::uint64_t>(szSource[1]) << 8ULL)) :
				nLength == 1U ? ProcessBlock(szSource, nLength - 1U, (ullHash ^ static_cast<std::uint64_t>(szSource[0])) * Q_HASH_MURMUR2_64_MODULO) :
				XorShr(XorShr(ullHash, 47ULL) * Q_HASH_MURMUR2_64_MODULO, 47ULL);
		}
	}

	/// @param[in] pSource buffer for which the hash will be generated
	/// @param[in] nLength length of the source buffer in bytes
	/// @param[in] ullSeed initial key of the hash generation
	/// @returns: calculated hash of the given buffer
	inline MurMur264_t Hash(const std::uint8_t* pSource, std::size_t nLength, const std::uint64_t ullSeed = 0ULL) noexcept
	{
		MurMur264_t uHash = ullSeed ^ (nLength * Q_HASH_MURMUR2_64_MODULO);

		while (nLength >= sizeof(std::uint64_t))
		{
			// endian-independent load of 8 bytes
			std::uint64_t ullBlock;
			if constexpr (std::endian::native == std::endian::little)
				ullBlock = *reinterpret_cast<const std::uint64_t*>(pSource);
			else
				ullBlock = (static_cast<std::uint64_t>(pSource[0]) | (static_cast<std::uint64_t>(pSource[1]) << 8ULL) | (static_cast<std::uint64_t>(pSource[2]) << 16ULL) | (static_cast<std::uint64_t>(pSource[3]) << 24ULL) | (static_cast<std::uint64_t>(pSource[4]) << 32ULL) | (static_cast<std::uint64_t>(pSource[5]) << 40ULL) | (static_cast<std::uint64_t>(pSource[6]) << 48ULL) | (static_cast<std::uint64_t>(pSource[7]) << 56ULL));

			ullBlock *= Q_HASH_MURMUR2_64_MODULO;
			ullBlock ^= ullBlock >> 47U;
			ullBlock *= Q_HASH_MURMUR2_64_MODULO;

			uHash ^= ullBlock;
			uHash *= Q_HASH_MURMUR2_64_MODULO;

			pSource += sizeof(std::uint64_t);
			nLength -= sizeof(std::uint64_t);
		}

		switch (nLength)
		{
		case 7U:
			uHash ^= static_cast<std::uint64_t>(pSource[6]) << 48U;
			[[fallthrough]];
		case 6U:
			uHash ^= static_cast<std::uint64_t>(pSource[5]) << 40U;
			[[fallthrough]];
		case 5U:
			uHash ^= static_cast<std::uint64_t>(pSource[4]) << 32U;
			[[fallthrough]];
		case 4U:
			uHash ^= static_cast<std::uint64_t>(pSource[3]) << 24U;
			[[fallthrough]];
		case 3U:
			uHash ^= static_cast<std::uint64_t>(pSource[2]) << 16U;
			[[fallthrough]];
		case 2U:
			uHash ^= static_cast<std::uint64_t>(pSource[1]) << 8U;
			[[fallthrough]];
		case 1U:
			uHash ^= static_cast<std::uint64_t>(pSource[0]);
			uHash *= Q_HASH_MURMUR2_64_MODULO;
			break;
		default:
			break;
		}

		uHash ^= uHash >> 47U;
		uHash *= Q_HASH_MURMUR2_64_MODULO;
		uHash ^= uHash >> 47U;
		return uHash;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] ullSeed initial key of the hash generation
	/// @returns: calculated hash of the given string
	inline MurMur264_t Hash(const char* szSource, const std::uint64_t ullSeed = 0ULL) noexcept
	{
#ifdef Q_CRT
		const std::size_t nLength = CRT::StringLength(szSource);
#else
		const std::size_t nLength = ::strlen(szSource);
#endif
		return Hash(reinterpret_cast<const std::uint8_t*>(szSource), nLength, ullSeed);
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] ullSeed initial key of the hash generation
	/// @returns: calculated at compile-time hash of the given string
	//template <typename T = char> requires (std::is_same_v<T, char> || std::is_same_v<T, wchar_t>)
	consteval MurMur264_t HashConst(const char* szSource, const std::uint64_t ullSeed = 0ULL) noexcept
	{
#ifdef Q_CRT
		const std::size_t nLength = CRT::StringLength(szSource);
#else
		const char* szSourceEnd = szSource;
		while (*szSourceEnd != '\0')
			++szSourceEnd;

		const std::size_t nLength = szSourceEnd - szSource;
#endif
		return DETAIL::ProcessBlock(szSource, nLength, ullSeed ^ (nLength * Q_HASH_MURMUR2_64_MODULO));
	}
}
