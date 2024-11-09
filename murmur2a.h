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

#define Q_HASH_MURMUR2A

#ifndef Q_HASH_MURMUR2A_MODULO
#define Q_HASH_MURMUR2A_MODULO 0x5BD1E995
#endif

using MurMur2A_t = std::uint32_t;

/*
 * 32-BIT MURMUR2 ALTERNATIVE HASH ALGORITHM
 * @credits: Austin Appleby
 */
namespace MURMUR2A
{
	namespace DETAIL
	{
		consteval std::uint32_t XorShr(const std::uint32_t uValue, const std::uint32_t uShift)
		{
			return uValue ^ (uValue >> uShift);
		}

		consteval MurMur2A_t Body(const char* szSource, const std::uint32_t nLength, const MurMur2A_t uHash)
		{
			return nLength >= 4U ? Body(szSource + 4U, nLength - 4U, (uHash * Q_HASH_MURMUR2_MODULO) ^ (XorShr((static_cast<std::uint32_t>(szSource[0]) | (static_cast<std::uint32_t>(szSource[1]) << 8U) | (static_cast<std::uint32_t>(szSource[2]) << 16U) | (static_cast<std::uint32_t>(szSource[3]) << 24U)) * Q_HASH_MURMUR2_MODULO, 24U) * Q_HASH_MURMUR2_MODULO)) : uHash;
		}

		consteval MurMur2A_t Tail(const char* szSource, const std::uint32_t nLength, const MurMur2A_t uHash)
		{
			return (uHash * Q_HASH_MURMUR2A_MODULO) ^ (XorShr((nLength == 3U ? (szSource[0] | (szSource[1] << 8U) | (szSource[2] << 16U)) : nLength == 2U ? (szSource[0] | (szSource[1] << 8U)) : nLength == 1U ? szSource[0] : 0U) * Q_HASH_MURMUR2A_MODULO, 24U) * Q_HASH_MURMUR2A_MODULO);
		}

		consteval MurMur2A_t ProcessBlock(const char* szSource, const std::uint32_t nLength, const MurMur2A_t uHash)
		{
			return XorShr(XorShr((Tail(szSource + (nLength & ~3U), nLength & 3U, Body(szSource, nLength, uHash)) * Q_HASH_MURMUR2A_MODULO) ^ (XorShr(nLength * Q_HASH_MURMUR2A_MODULO, 24U) * Q_HASH_MURMUR2A_MODULO), 13U) * Q_HASH_MURMUR2A_MODULO, 15U);
		}
	}

	/// @param[in] pSource buffer for which the hash will be generated
	/// @param[in] nLength length of the source buffer in bytes
	/// @param[in] uSeed initial key of the hash generation
	/// @returns: calculated hash of the given buffer
	inline MurMur2A_t Hash(const std::uint8_t* pSource, std::uint32_t nLength, const std::uint32_t uSeed = 0U) noexcept
	{
		MurMur2A_t uHash = uSeed;

		std::uint32_t nRemainingLength = nLength;
		while (nRemainingLength >= sizeof(std::uint32_t))
		{
			// endian-independent load of 4 bytes
			std::uint32_t uBlock;
			if constexpr (std::endian::native == std::endian::little)
				uBlock = *reinterpret_cast<const std::uint32_t*>(pSource);
			else
				uBlock = (static_cast<std::uint32_t>(pSource[0]) | (static_cast<std::uint32_t>(pSource[1]) << 8U) | (static_cast<std::uint32_t>(pSource[2]) << 16U) | (static_cast<std::uint32_t>(pSource[3]) << 24U));

			uBlock *= Q_HASH_MURMUR2A_MODULO;
			uBlock ^= uBlock >> 24U;
			uBlock *= Q_HASH_MURMUR2A_MODULO;

			uHash *= Q_HASH_MURMUR2A_MODULO;
			uHash ^= uBlock;

			pSource += sizeof(std::uint32_t);
			nRemainingLength -= sizeof(std::uint32_t);
		}

		MurMur2A_t uTail = 0U;
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
			uTail *= Q_HASH_MURMUR2A_MODULO;
			uTail ^= uTail >> 24U;
			uTail *= Q_HASH_MURMUR2A_MODULO;
			break;
		default:
			break;
		}

		uHash *= Q_HASH_MURMUR2A_MODULO;
		uHash ^= uTail;

		nLength *= Q_HASH_MURMUR2A_MODULO;
		nLength ^= nLength >> 24U;
		nLength *= Q_HASH_MURMUR2A_MODULO;

		uHash *= Q_HASH_MURMUR2A_MODULO;
		uHash ^= nLength;

		uHash ^= uHash >> 13U;
		uHash *= Q_HASH_MURMUR2A_MODULO;
		uHash ^= uHash >> 15U;
		return uHash;
	}
	
	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uSeed initial key of the hash generation
	/// @returns: calculated hash of the given string
	inline MurMur2A_t Hash(const char* szSource, const std::uint32_t uSeed = 0U) noexcept
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
	consteval MurMur2A_t HashConst(const char* szSource, const std::uint32_t uSeed = 0U) noexcept
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
