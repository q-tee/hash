#pragma once
// used: [stl] size_t
#include <cstddef>
// used: [stl] uint64_t
#include <cstdint>

#define Q_HASH_FNV1A_64

#ifndef Q_HASH_FNV1A_64_BASIS
#define Q_HASH_FNV1A_64_BASIS 0xCBF29CE484222325
#endif

#ifndef Q_HASH_FNV1A_64_PRIME
#define Q_HASH_FNV1A_64_PRIME 0x100000001B3
#endif

using FNV1A64_t = std::uint64_t;

/*
 * 64-BIT FOWLER-NOLL-VO ALTERNATIVE HASH ALGORITHM
 * @credits: http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 */
namespace FNV1A_64
{
	/* @section: get */
	/// @param[in] pSource buffer for which the hash will be generated
	/// @param[in] nLength length of the source buffer in bytes
	/// @param[in] ullBasis initial key of the hash generation
	/// @returns: calculated hash of the given buffer
	inline FNV1A64_t Hash(const std::uint8_t* pSource, std::size_t nLength, FNV1A64_t ullBasis = Q_HASH_FNV1A_64_BASIS) noexcept
	{
		while (nLength-- != 0U)
			ullBasis = (ullBasis ^ *pSource++) * Q_HASH_FNV1A_64_PRIME;

		return ullBasis;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] ullBasis initial key of the hash generation
	/// @returns: calculated hash of the given string
	constexpr FNV1A64_t Hash(const char* szSource, FNV1A64_t ullBasis = Q_HASH_FNV1A_64_BASIS) noexcept
	{
		while (*szSource != '\0')
			ullBasis = (ullBasis ^ static_cast<std::uint8_t>(*szSource++)) * Q_HASH_FNV1A_64_PRIME;

		return ullBasis;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] ullBasis initial key of the hash generation
	/// @returns: calculated at compile-time hash of the given string
	template <typename T = char> requires (std::is_same_v<T, char> || std::is_same_v<T, wchar_t>)
	consteval FNV1A64_t HashConst(const char* szSource, const FNV1A64_t ullBasis = Q_HASH_FNV1A_64_BASIS) noexcept
	{
		return (*szSource == '\0') ? ullBasis : HashConst(szSource + 1, (ullBasis ^ static_cast<std::uint8_t>(*szSource)) * Q_HASH_FNV1A_64_PRIME);
	}
}
