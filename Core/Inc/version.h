/**
 * @file  version.h
 * @brief Firmware semantic version.  Bump MINOR on feature changes, PATCH on fixes.
 *
 * Packed word layout:  (MAJOR << 16) | (MINOR << 8) | PATCH
 * Stored in the DTC flash page header at offset 4 (LE uint32_t).
 * Transmitted in the PROV_TYPE_DTC UART payload bytes [1..3].
 */

#ifndef VERSION_H
#define VERSION_H

#include <stdint.h>

#define FW_VERSION_MAJOR  1u
#define FW_VERSION_MINOR  0u
#define FW_VERSION_PATCH  0u

#define FW_VERSION_WORD   (((uint32_t)FW_VERSION_MAJOR << 16u) | \
                           ((uint32_t)FW_VERSION_MINOR <<  8u) | \
                            (uint32_t)FW_VERSION_PATCH)

#endif /* VERSION_H */
