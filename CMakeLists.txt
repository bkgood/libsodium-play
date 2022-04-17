cmake_minimum_required(VERSION 3.14)

project(nacl-init C)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)

add_executable(main main.c)

target_link_libraries(main PUBLIC PkgConfig::LIBSODIUM)
target_include_directories(main PUBLIC ${SODIUM_INCLUDE_DIRS})
target_compile_options(main PUBLIC ${SODIUM_CFLAGS_OTHER})
