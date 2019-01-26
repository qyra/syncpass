cmake_minimum_required (VERSION 2.6)
project (Syncpass)

set (Syncpass_VERSION_MAJOR 0)
set (Syncpass_VERSION_MINOR 1)

set (CMAKE_CXX_STANDARD 14)

include_directories("${PROJECT_SOURCE_DIR}/include")
# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")

# If in debug mode, use address sanitizer.
set(COMMON_FLAGS "-Wall -Wno-unused-variable")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COMMON_FLAGS} -g -O1 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")

# Don't use address san with kcachegrind.
#~ set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -Wall")

# If in release enable higher optimization level
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${COMMON_FLAGS} -O3")

# Modify this to add new source files. Their .h files should be in the include folder.
add_executable(syncpass src/main.cpp)

# Add OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(syncpass OpenSSL::SSL)

