# Build the NXP Plug&Trust SDK sources into the static libraries
# that wolfSSL's configure expects at specific paths under build/.
CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)
project(se050_sdk_libs)

SET(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE(${SIMW_LIB_DIR}/simw_lib.cmake)

# 1. libSSS_APIs.a in build/sss/
#
# HostCrypto backend is picked by PTMW_HostCrypto (set at cmake configure):
#   OPENSSL  → sss/src/openssl/fsl_sss_openssl_apis.c (sdk-test uses this)
#   WOLFSSL  → sss/src/wolfssl/fsl_sss_wolfssl_apis.c, added by wolfSSL's OSP
#              middleware patch (wolfcrypt-test uses this)
FILE(GLOB SSS_SOURCES
    ${SIMW_LIB_DIR}/sss/src/*.c
    ${SIMW_LIB_DIR}/sss/src/se05x/*.c
    ${SIMW_LIB_DIR}/sss/src/keystore/*.c
)
IF("${PTMW_HostCrypto}" STREQUAL "WOLFSSL")
    LIST(APPEND SSS_SOURCES ${SIMW_LIB_DIR}/sss/src/wolfssl/fsl_sss_wolfssl_apis.c)
ELSE()
    LIST(APPEND SSS_SOURCES ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c)
ENDIF()
ADD_LIBRARY(SSS_APIs STATIC ${SSS_SOURCES})
TARGET_INCLUDE_DIRECTORIES(SSS_APIs PUBLIC ${SIMW_INC_DIR})
IF("${PTMW_HostCrypto}" STREQUAL "WOLFSSL")
    TARGET_LINK_LIBRARIES(SSS_APIs PUBLIC wolfssl)
ENDIF()
SET_TARGET_PROPERTIES(SSS_APIs PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/sss)

# 2. libex_common.a in build/sss/ex/src/
FILE(GLOB EX_SOURCES
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_boot.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_boot_connectstring.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_se05x.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_se05x_auth.c
)
# Platform SCP03: ex_sss_se05x_auth.c references scp03_keys_from_path() (the
# EX_SSS_BOOT_SCP03_PATH key-file loader) whenever SCP03 is compiled in on
# Linux. Gated so Auth=None builds stay byte-identical. The DEFINED check
# matters because an unset variable would make the STREQUAL test true and pull
# the SCP03 sources into a plain build.
IF(DEFINED PTMW_SE05X_Auth AND NOT "${PTMW_SE05X_Auth}" STREQUAL "None")
    LIST(APPEND EX_SOURCES ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_scp03_auth.c)
ENDIF()
ADD_LIBRARY(ex_common STATIC ${EX_SOURCES})
TARGET_INCLUDE_DIRECTORIES(ex_common PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(ex_common PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/sss/ex/src)

# 3. libse05x.a in build/hostlib/hostLib/se05x/
FILE(GLOB SE05X_SOURCES
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x/src/*.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x_03_xx_xx/*.c
)
ADD_LIBRARY(se05x STATIC ${SE05X_SOURCES})
TARGET_INCLUDE_DIRECTORIES(se05x PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(se05x PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/hostlib/hostLib/se05x)

# 4. liba7x_utils.a in build/hostlib/hostLib/
FILE(GLOB A7X_SOURCES
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/linux/i2c_a7.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/rsp/se05x_reset.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/generic/sm_timer.c
)
ADD_LIBRARY(a7x_utils STATIC ${A7X_SOURCES})
TARGET_INCLUDE_DIRECTORIES(a7x_utils PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(a7x_utils PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/hostlib/hostLib)

# 5. libmwlog.a in build/hostlib/hostLib/libCommon/log/
ADD_LIBRARY(mwlog STATIC ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/log/nxLog.c)
TARGET_INCLUDE_DIRECTORIES(mwlog PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(mwlog PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/hostlib/hostLib/libCommon/log)

# 6. libsmCom.a in build/hostlib/hostLib/libCommon/
FILE(GLOB SMCOM_SOURCES
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/smCom.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/smComT1oI2C.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/*.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/infra/*.c
)
# Platform SCP03 command wrapping (nxScp03_GP_InitializeUpdate /
# ExternalAuthenticate / Encrypt / Decrypt). The libCommon/nxScp/ directory
# is not covered by the globs above. Gated so Auth=None builds are unchanged;
# see the DEFINED note above.
IF(DEFINED PTMW_SE05X_Auth AND NOT "${PTMW_SE05X_Auth}" STREQUAL "None")
    LIST(APPEND SMCOM_SOURCES ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c)
ENDIF()
ADD_LIBRARY(smCom STATIC ${SMCOM_SOURCES})
TARGET_INCLUDE_DIRECTORIES(smCom PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(smCom PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/hostlib/hostLib/libCommon)
