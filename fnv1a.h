#pragma once
// used: [stl] uint32_t
#include <cstdint>

#define Q_HASH_FNV1A

#ifndef Q_HASH_FNV1A_BASIS
#define Q_HASH_FNV1A_BASIS 0x811C9DC5
#endif
#ifndef Q_HASH_FNV1A_PRIME
#define Q_HASH_FNV1A_PRIME 0x1000193
#endif

using FNV1A_t = std::uint32_t;

/*
 * 32-BIT FOWLER-NOLL-VO ALTERNATIVE HASH ALGORITHM
 * @credits: http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 */
namespace FNV1A
{
	/// @param[in] pSource buffer for which the hash will be generated
	/// @param[in] nLength length of the source buffer in bytes
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: calculated hash of the given buffer
	inline FNV1A_t Hash(const std::uint8_t* pSource, std::uint32_t nLength, FNV1A_t uBasis = Q_HASH_FNV1A_BASIS) noexcept
	{
		while (nLength-- != 0U)
			uBasis = (uBasis ^ *pSource++) * Q_HASH_FNV1A_PRIME;

		return uBasis;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: calculated hash of the given string
	constexpr FNV1A_t Hash(const char* szSource, FNV1A_t uBasis = Q_HASH_FNV1A_BASIS) noexcept
	{
		while (*szSource != '\0')
			uBasis = (uBasis ^ static_cast<std::uint8_t>(*szSource++)) * Q_HASH_FNV1A_PRIME;

		return uBasis;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: calculated at compile-time hash of the given string
	consteval FNV1A_t HashConst(const char* szSource, const FNV1A_t uBasis = Q_HASH_FNV1A_BASIS) noexcept
	{
		return (*szSource == '\0') ? uBasis : HashConst(szSource + 1, (uBasis ^ static_cast<std::uint8_t>(*szSource)) * Q_HASH_FNV1A_PRIME);
	}
}
