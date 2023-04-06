project(pkw)

set(CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
        ${CMAKE_MODULE_PATH})

include_directories(pkw)

set(HEADER_FILES
        secure_memzero.h
        secure_byte_buffer.h
        pkw/pkw.h
        pkw/helpers/password_encrypt.h
        pkw/naive_pkw.h
        pkw/exceptions.h
        pkw/pprf_aead_pkw.h
        pprf/ggm_pprf.h
        pprf/pprf_exceptions.h
        pprf/pprf_key_serializer.h
        )

set(SOURCE_FILES
        secure_byte_buffer.cpp
        pkw/pkw.cpp
        pkw/helpers/password_encrypt.cpp
        pkw/naive_pkw.cpp
        pkw/pprf_aead_pkw.cpp
        pprf/ggm_pprf.cpp
        pprf/pprf_key_serializer.cpp
        pprf/ggm_pprf_key.cpp pprf/secret_root.cpp)

add_library(PKWLib STATIC ${HEADER_FILES} ${SOURCE_FILES})

find_library(CRYPTO_PP cryptoPP REQUIRED)
find_path(CRYPTO_PP_INC cryptoPP REQUIRED)

target_include_directories(PKWLib PUBLIC ${CRYPTO_PP_INC})
target_link_libraries(PKWLib ${CRYPTO_PP})

# export library: from https://cmake.org/cmake/help/latest/guide/importing-exporting/index.html#exporting-targets
include(GNUInstallDirs)

install(TARGETS PKWLib
        EXPORT PKWLibTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )

message("libdir at " ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${SOURCE_FILES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT PKWLibTargets
        FILE PKWLibTargets.cmake
        NAMESPACE PKW::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PKWLib
        )

include(CMakePackageConfigHelpers)
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/PKWLibConfig.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PKWLib
        )

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/PKWLibConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/PKWLibConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PKWLib
        )