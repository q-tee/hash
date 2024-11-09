#pragma once
// used: [stl] uint32_t
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

#define Q_HASH_MURMUR2

#ifndef Q_HASH_MURMUR2_MODULO
#define Q_HASH_MURMUR2_MODULO 0x5BD1E995
#endif

using MurMur2_t = std::uint32_t;

/*
 * 32-BIT MURMUR2 HASHING ALGORITHM
 * @credits: Austin Appleby
 */
namespace MURMUR2
{
	namespace DETAIL
	{
		consteval std::uint32_t XorShr(const std::uint32_t uValue, const std::uint32_t uShift)
		{
			return uValue ^ (uValue >> uShift);
		}

		consteval MurMur2_t ProcessBlock(const char* szSource, const std::uint32_t nLength, const MurMur2_t uHash)
		{
			return
				nLength >= 4U ? ProcessBlock(szSource + 4U, nLength - 4U, (uHash * Q_HASH_MURMUR2_MODULO) ^ (XorShr(static_cast<std::uint32_t>(szSource[0] | (szSource[1] << 8U) | (szSource[2] << 16U) | (szSource[3] << 24U)) * Q_HASH_MURMUR2_MODULO, 24U) * Q_HASH_MURMUR2_MODULO)) :
				nLength == 3U ? ProcessBlock(szSource, nLength - 1U, uHash ^ (szSource[2] << 16U)) :
				nLength == 2U ? ProcessBlock(szSource, nLength - 1U, uHash ^ (szSource[1] << 8U)) :
				nLength == 1U ? ProcessBlock(szSource, nLength - 1U, (uHash ^ szSource[0]) * Q_HASH_MURMUR2_MODULO) :
				XorShr(XorShr(uHash, 13U) * Q_HASH_MURMUR2_MODULO, 15U);
		}
	}

	/// @param[in] pSource buffer for which the hash will be generated
	/// @param[in] nLength length of the source buffer in bytes
	/// @param[in] uSeed initial key of the hash generation
	/// @returns: calculated hash of the given buffer
	inline MurMur2_t Hash(const std::uint8_t* pSource, std::uint32_t nLength, const std::uint32_t uSeed = 0U) noexcept
	{
		MurMur2_t uHash = uSeed ^ nLength;

		while (nLength >= sizeof(std::uint32_t))
		{
			// endian-independent load of 4 bytes
			std::uint32_t uBlock;
			if constexpr (std::endian::native == std::endian::little)
				uBlock = *reinterpret_cast<const std::uint32_t*>(pSource);
			else
				uBlock = (static_cast<std::uint32_t>(pSource[0]) | (static_cast<std::uint32_t>(pSource[1]) << 8U) | (static_cast<std::uint32_t>(pSource[2]) << 16U) | (static_cast<std::uint32_t>(pSource[3]) << 24U));

			uBlock *= Q_HASH_MURMUR2_MODULO;
			uBlock ^= uBlock >> 24U;
			uBlock *= Q_HASH_MURMUR2_MODULO;

			uHash *= Q_HASH_MURMUR2_MODULO;
			uHash ^= uBlock;

			pSource += sizeof(std::uint32_t);
			nLength -= sizeof(std::uint32_t);
		}

		switch (nLength)
		{
		case 3U:
			uHash ^= pSource[2] << 16U;
			[[fallthrough]];
		case 2U:
			uHash ^= pSource[1] << 8U;
			[[fallthrough]];
		case 1U:
			uHash ^= pSource[0];
			uHash *= Q_HASH_MURMUR2_MODULO;
			break;
		default:
			break;
		}

		uHash ^= uHash >> 13U;
		uHash *= Q_HASH_MURMUR2_MODULO;
		uHash ^= uHash >> 15U;
		return uHash;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uSeed initial key of the hash generation
	/// @returns: calculated hash of the given string
	inline MurMur2_t Hash(const char* szSource, const std::uint32_t uSeed = 0U) noexcept
	{
#ifdef Q_CRT
		const std::size_t nLength = CRT::StringLength(szSource);
#else
		const std::size_t nLength = ::strlen(szSource);
#endif
		return Hash(reinterpret_cast<const std::uint8_t*>(szSource), static_cast<std::uint32_t>(nLength), uSeed);
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uSeed initial key of the hash generation
	/// @returns: calculated at compile-time hash of given string
	consteval MurMur2_t HashConst(const char* szSource, const std::uint32_t uSeed = 0U) noexcept
	{
#ifdef Q_CRT
		const std::size_t nLength = CRT::StringLength(szSource);
#else
		const char* szSourceEnd = szSource;
		while (*szSourceEnd != '\0')
			++szSourceEnd;

		const std::size_t nLength = szSourceEnd - szSource;
#endif
		return DETAIL::ProcessBlock(szSource, static_cast<std::uint32_t>(nLength), uSeed ^ static_cast<std::uint32_t>(nLength));
	}
}
