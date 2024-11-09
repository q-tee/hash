#pragma once
// used: [stl] uint32_t
#include <cstdint>
// used: [stl] endian, rotl
#include <bit>

#if Q_HAS_INCLUDE("q-tee/crt/crt.h")
// used: stringlength
#include <q-tee/crt/crt.h>
#else
// used: [crt] strlen
#include <cstring>
#endif

#define Q_HASH_MURMUR3

#ifndef Q_HASH_MURMUR3_FIRST
#define Q_HASH_MURMUR3_FIRST 0xCC9E2D51
#endif

#ifndef Q_HASH_MURMUR3_SECOND
#define Q_HASH_MURMUR3_SECOND 0x1B873593
#endif

#ifndef Q_HASH_MURMUR3_THIRD
#define Q_HASH_MURMUR3_THIRD 0xE6546B64
#endif

#ifndef Q_HASH_MURMUR3_AVALANCHE_FIRST
#define Q_HASH_MURMUR3_AVALANCHE_FIRST 0x85EBCA6B
#endif

#ifndef Q_HASH_MURMUR3_AVALANCHE_SECOND
#define Q_HASH_MURMUR3_AVALANCHE_SECOND 0xC2B2AE35
#endif

using MurMur3_t = std::uint32_t;

/*
 * 32-BIT MURMUR3 HASH ALGORITHM
 * @credits: Austin Appleby
 */
namespace MURMUR3
{
	namespace DETAIL
	{
		consteval std::uint32_t XorShr(const std::uint32_t uValue, const std::uint32_t uShift) noexcept
		{
			return uValue ^ (uValue >> uShift);
		}

		consteval MurMur3_t Body(const char* szSource, const std::uint32_t nLength, const MurMur3_t uHash) noexcept
		{
			return nLength >= 4U ? Body(szSource + 4U, nLength - 4U, std::rotl(uHash ^ (std::rotl((static_cast<std::uint32_t>(szSource[0]) | (static_cast<std::uint32_t>(szSource[1]) << 8U) | (static_cast<std::uint32_t>(szSource[2]) << 16U) | (static_cast<std::uint32_t>(szSource[3]) << 24U)) * Q_HASH_MURMUR3_FIRST, 15U) * Q_HASH_MURMUR3_SECOND), 13U) * 5U + Q_HASH_MURMUR3_THIRD) : uHash;
		}

		consteval MurMur3_t Tail(const char* szSource, const std::uint32_t nLength, const MurMur3_t uHash) noexcept
		{
			return uHash ^ (std::rotl((nLength == 3U ? (szSource[0] | (szSource[1] << 8U) | (szSource[2] << 16U)) : nLength == 2U ? (szSource[0] | (szSource[1] << 8U)) : nLength == 1U ? szSource[0] : 0U) * Q_HASH_MURMUR3_FIRST, 15U) * Q_HASH_MURMUR3_SECOND);
		}

		consteval MurMur3_t ProcessBlock(const char* szSource, const std::uint32_t nLength, const MurMur3_t uHash) noexcept
		{
			return XorShr(XorShr(XorShr(Tail(szSource + (nLength & ~3U), nLength & 3U, Body(szSource, nLength, uHash)) ^ nLength, 16U) * Q_HASH_MURMUR3_AVALANCHE_FIRST, 13U) * Q_HASH_MURMUR3_AVALANCHE_SECOND, 16U);
		}
	}

	/// @param[in] pSource buffer for which the hash will be generated
	/// @param[in] nLength length of the source buffer in bytes
	/// @param[in] uSeed initial key of the hash generation
	/// @returns: calculated hash of the given buffer
	inline MurMur3_t Hash(const std::uint8_t* pSource, const std::uint32_t nLength, const std::uint32_t uSeed = 0U) noexcept
	{
		MurMur3_t uHash = uSeed;

		std::uint32_t nRemainingLength = nLength;
		while (nRemainingLength >= sizeof(std::uint32_t))
		{
			// endian-independent load of 4 bytes
			std::uint32_t uBlock;
			if constexpr (std::endian::native == std::endian::little)
				uBlock = *reinterpret_cast<const std::uint32_t*>(pSource);
			else
				uBlock = (static_cast<std::uint32_t>(pSource[0]) | (static_cast<std::uint32_t>(pSource[1]) << 8U) | (static_cast<std::uint32_t>(pSource[2]) << 16U) | (static_cast<std::uint32_t>(pSource[3]) << 24U));

			uBlock *= Q_HASH_MURMUR3_FIRST;
			uBlock = std::rotl(uBlock, 15U);
			uBlock *= Q_HASH_MURMUR3_SECOND;

			uHash ^= uBlock;
			uHash = std::rotl(uHash, 13U);
			uHash = uHash * 5U + Q_HASH_MURMUR3_THIRD;

			pSource += sizeof(std::uint32_t);
			nRemainingLength -= sizeof(std::uint32_t);
		}

		// process the remaining length
		std::uint32_t uTail = 0U;
		switch (nRemainingLength)
		{
		case 3U:
			uTail ^= pSource[2] << 16U;
			[[fallthrough]];
		case 2U:
			uTail ^= pSource[1] << 8U;
			[[fallthrough]];
		case 1U:
			uTail ^= pSource[0];
			uTail *= Q_HASH_MURMUR3_FIRST;
			uTail = std::rotl(uTail, 15U);
			uTail *= Q_HASH_MURMUR3_SECOND;
			uHash ^= uTail;
			break;
		default:
			break;
		}

		// finalize
		uHash ^= nLength;
		// force all bits of a hash block to avalanche
		uHash ^= uHash >> 16U;
		uHash *= Q_HASH_MURMUR3_AVALANCHE_FIRST;
		uHash ^= uHash >> 13U;
		uHash *= Q_HASH_MURMUR3_AVALANCHE_SECOND;
		uHash ^= uHash >> 16U;
		return uHash;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uSeed initial key of the hash generation
	/// @returns: calculated hash of the given string
	inline MurMur3_t Hash(const char* szSource, const std::uint32_t uSeed = 0U) noexcept
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
	/// @returns: calculated at compile-time hash of the given string
	//template <typename T = char> requires (std::is_same_v<T, char> || std::is_same_v<T, wchar_t>)
	consteval MurMur3_t HashConst(const char* szSource, const std::uint32_t uSeed = 0U) noexcept
	{
#ifdef Q_CRT
		const std::size_t nLength = CRT::StringLength(szSource);
#else
		const char* szSourceEnd = szSource;
		while (*szSourceEnd != '\0')
			++szSourceEnd;

		const std::size_t nLength = szSourceEnd - szSource;
#endif
		return DETAIL::ProcessBlock(szSource, static_cast<std::uint32_t>(nLength), uSeed);
	}
}
