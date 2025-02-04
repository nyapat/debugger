cmake_minimum_required(VERSION 3.10)
project(MyProject CXX)

set(CMAKE_CXX_STANDARD 17)

include_directories(ext/libelfin include)

# Build libelfin libraries
add_custom_command(
    OUTPUT ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
           ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so
    COMMAND make
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
    COMMENT "Building libelfin"
)

# Custom target that ensures the above command runs
add_custom_target(libelfin ALL DEPENDS
    ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
    ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so
)

# Add the built libraries as imported targets
add_library(libdwarf++ SHARED IMPORTED)
set_target_properties(libdwarf++ PROPERTIES
    IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
)

add_library(libelf++ SHARED IMPORTED)
set_target_properties(libelf++ PROPERTIES
    IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so
)

# Define the executable
add_executable(myapp src/main.cpp)

# Link against the imported libraries
target_link_libraries(myapp
    linenoise.so
    libdwarf++
    libelf++
)

# Ensure myapp depends on libelfin so it's built first
add_dependencies(myapp libelfin)
