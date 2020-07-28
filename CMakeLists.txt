cmake_minimum_required(VERSION 2.8)
project(SilverLock)

if(NOT CMAKE_BUILD_TYPE)
  set(
    CMAKE_BUILD_TYPE
    Release
    CACHE
      STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()

include_directories(vendor)

add_executable(silverlock
    src/crypto.cpp
    src/main.cpp
    src/utils.cpp)
    
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM libsodium)

find_path(SODIUM_INCLUDE_DIR sodium.h HINTS ${LIBSODIUM_INCLUDE_DIRS} /usr/local/include /opt/local/include /opt/include)
find_library(SODIUM_LIBRARY NAMES sodium HINTS ${LIBSODIUM_LIBRARY_DIRS} /usr/local/lib /opt/local/lib /opt/lib)

target_include_directories(silverlock PUBLIC ${SODIUM_INCLUDE_DIR})
target_compile_options(silverlock PUBLIC ${LIBSODIUM_CFLAGS})
target_link_libraries(silverlock ${SODIUM_LIBRARY})

if (NOT MSVC AND CMAKE_STRIP)
  add_custom_command(TARGET silverlock POST_BUILD
    COMMAND ${CMAKE_STRIP} ${STRIP_FLAGS} $<TARGET_FILE:silverlock>)
endif()

install(TARGETS silverlock DESTINATION bin)
