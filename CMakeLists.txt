# TODO: Wait for cmake version to be fixed, until then enforce this version.https://www.reddit.com/r/archlinux/comments/1bno6fl/the_latest_version_of_cmake_fails_to_build/
cmake_minimum_required(VERSION 3.28.3)
project(CookieJar VERSION 0.1.0 LANGUAGES C)

set(CMAKE_COLOR_DIAGNOSTICS ON)

FILE(GLOB Source CONFIGURE_DEPENDS src/*.c )
FILE(GLOB Includes CONFIGURE_DEPENDS includes/*.h)

include(CMakeScripts/FindPCAP.cmake)


set(CMAKE_BUILD_TYPE Debug)
add_executable(CookieJar ${Source})
add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)

target_link_libraries(CookieJar ${PCAP_LIBRARY})
