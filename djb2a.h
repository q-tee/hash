#pragma once
// used: [stl] uint32_t
#include <cstdint>

#define Q_HASH_DJB2A

#ifndef Q_HASH_DJB2A_BASIS
#define Q_HASH_DJB2A_BASIS 0x1505
#endif

using DJB2A_t = std::uint32_t;

/*
 * DANIEL J. BERNSTEIN'S ALTERNATIVE HASH ALGORITHM
 */
namespace DJB2A
{
	/// @param[in] pSource buffer for which the hash will be generated
	/// @param[in] nLength length of the source buffer in bytes
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: calculated hash of the given buffer
	inline DJB2A_t Hash(const std::uint8_t* pSource, std::uint32_t nLength, DJB2A_t uBasis = Q_HASH_DJB2A_BASIS) noexcept
	{
		while (nLength-- != 0U)
			uBasis = (uBasis + (uBasis << 5U)) ^ *pSource++;

		return uBasis;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: calculated hash of the given string
	constexpr DJB2A_t Hash(const char* szSource, DJB2A_t uBasis = Q_HASH_DJB2A_BASIS) noexcept
	{
		while (*szSource != '\0')
			uBasis = (uBasis + (uBasis << 5U)) ^ static_cast<std::uint8_t>(*szSource++);

		return uBasis;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: calculated at compile-time hash of the given string
	consteval DJB2A_t HashConst(const char* szSource, const DJB2A_t uBasis = Q_HASH_DJB2A_BASIS) noexcept
	{
		return (*szSource == '\0') ? uBasis : HashConst(szSource + 1, (uBasis + (uBasis << 5U)) ^ static_cast<std::uint8_t>(*szSource));
	}
}