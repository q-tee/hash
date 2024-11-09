# about
collection of lightweight implementations of the non-cryptographic hash algorithms, with compile-time variants for each.
list of the implemented algorithms:
- CRC 32
- DJB2 32
- DJB2A 32
- FNV1A 32/64
- MURMUR2 32/64
- MURMUR2A 32
- MURMUR3 32

# usage
all hash implementations have a uniform appearance, so the example usage also remains same for the all of them

to generate hash of the byte buffer:
```cpp
CRC32_t uHash = CRC32::Hash(pBuffer, nBufferSize);

// custom basis
CRC32_t uBasisHash = CRC32::Hash(pBuffer, nBufferSize, 0xFFFFFFFF);
```

to generate hash of string:
```cpp
CRC32_t uHash = CRC32::Hash(pBuffer, nBufferSize);

// custom basis
CRC32_t uBasisHash = CRC32::Hash(pBuffer, nBufferSize, 0xFFFFFFFF);
```

to generate hash of string, guaranteed at compile-time:
```cpp
CRC32_t uHash = CRC32::HashConst("example");

// custom basis
CRC32_t uBasisHash = CRC32::HashConst("example", 0xFFFFFFFF);
```

every hash's constant can be overwritten with appropriate definitions:
hash       | definition
---------- | ----------
CRC 32     | Q_HASH_CRC32_POLY
DJB2       | Q_HASH_DJB2_BASIS
DJB2A      | Q_HASH_DJB2A_BASIS
FNV1A      | Q_HASH_FNV1A_BASIS, Q_HASH_FNV1A_PRIME
FNV1A 64   | Q_HASH_FNV1A_64_BASIS, Q_HASH_FNV1A_64_PRIME
MURMUR2    | Q_HASH_MURMUR2_MODULO
MURMUR2 64 | Q_HASH_MURMUR2_64_MODULO
MURMUR2A   | Q_HASH_MURMUR2A_MODULO
MURMUR3    | Q_HASH_MURMUR3_FIRST, Q_HASH_MURMUR3_SECOND, Q_HASH_MURMUR3_THIRD, Q_HASH_MURMUR3_AVALANCHE_FIRST, Q_HASH_MURMUR3_AVALANCHE_SECOND

other options available for various algorithms:
hash   | definition          | note
------ | ------------------- | ----
CRC 32 | Q_HASH_CRC32_NO_LUT | do not use lookup table for the hash calculation, saves 1KB of the binary size