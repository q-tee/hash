#pragma once
// used: [stl] size_t
#include <cstddef>
// used: [stl] uint8_t, uint32_t
#include <cstdint>

#ifndef Q_HASH_CRC32_NO_LUT
// used: [stl] array
#include <array>
#endif

#ifndef Q_HASH_CRC32_POLY
#define Q_HASH_CRC32_POLY 0xEDB88320
#endif

using CRC32_t = std::uint32_t;

/*
 * 32-BIT CYCLIC REDUNDANCY CHECK HASH ALGORITHM
 */
namespace CRC32
{
#ifndef Q_HASH_CRC32_NO_LUT
	namespace DETAIL
	{
		consteval auto MakePolynomialLookup(const CRC32_t uPolynomial)
		{
			std::array<CRC32_t, 256U> arrTable;

			for (std::uint32_t uByte = 0U; uByte < 256U; ++uByte)
			{
				CRC32_t uResult = uByte;

				for (int i = 0U; i < 8; ++i)
					uResult = (uResult >> 1U) ^ (uPolynomial & -static_cast<std::int32_t>(uResult & 1U));

				arrTable[uByte] = uResult;
			}

			return arrTable;
		}

		/* @section: [internal] constants */
		// pre-computed LUT for a selected polynomial
		// @todo: avoid using 'std::array' as it may? involve SEH at run-time
		constexpr auto arrPolynomialLUT = MakePolynomialLookup(Q_HASH_CRC32_POLY);
	}
#endif

	/* @section: get */
	/// @param[in] pSource buffer for which the hash will be generated
	/// @param[in] nLength length of the source buffer in bytes
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: hash calculated at run-time of the given buffer
	inline CRC32_t Hash(const std::uint8_t* pSource, std::size_t nLength, CRC32_t uBasis = 0U)
	{
		uBasis = ~uBasis;

		while (nLength-- != 0U)
		{
		#ifndef Q_HASH_CRC32_NO_LUT
			uBasis = (uBasis >> 8U) ^ DETAIL::arrPolynomialLUT[(uBasis ^ *pSource++) & 0xFF];
		#else
			uBasis ^= *pSource++;
			for (unsigned int nTimes = 0U; nTimes < 8U; ++nTimes)
				uBasis = (uBasis >> 1U) ^ (Q_HASH_CRC32_POLY & -static_cast<std::int32_t>(uBasis & 1U));
		#endif
		}

		return ~uBasis;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: calculated hash of the given string
	constexpr CRC32_t Hash(const char* szSource, CRC32_t uBasis = 0U) noexcept
	{
		uBasis = ~uBasis;

		while (*szSource != '\0')
		{
		#ifndef Q_HASH_CRC32_NO_LUT
			uBasis = (uBasis >> 8U) ^ DETAIL::arrPolynomialLUT[(uBasis ^ static_cast<std::uint8_t>(*szSource++)) & 0xFF];
		#else
			uBasis ^= static_cast<std::uint8_t>(*szSource++);
			for (unsigned int nTimes = 0U; nTimes < 8U; ++nTimes)
				uBasis = (uBasis >> 1U) ^ (Q_HASH_CRC32_POLY & -static_cast<std::int32_t>(uBasis & 1U));
		#endif
		}

		return ~uBasis;
	}

	/// @param[in] szSource null-terminated string for which the hash will be generated
	/// @param[in] uBasis initial key of the hash generation
	/// @returns: calculated at compile-time hash of the given string
	consteval CRC32_t HashConst(const char* szSource, const CRC32_t uBasis = 0U) noexcept
	{
		return Hash(szSource, uBasis);
	}
}
