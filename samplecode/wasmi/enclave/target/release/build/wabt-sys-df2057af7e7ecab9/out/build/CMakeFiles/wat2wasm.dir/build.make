# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build

# Include any dependencies generated for this target.
include CMakeFiles/wat2wasm.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/wat2wasm.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/wat2wasm.dir/flags.make

CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o: CMakeFiles/wat2wasm.dir/flags.make
CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o: /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wat2wasm.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o -c /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wat2wasm.cc

CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wat2wasm.cc > CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.i

CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wat2wasm.cc -o CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.s

CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o.requires:

.PHONY : CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o.requires

CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o.provides: CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o.requires
	$(MAKE) -f CMakeFiles/wat2wasm.dir/build.make CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o.provides.build
.PHONY : CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o.provides

CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o.provides.build: CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o


# Object files for target wat2wasm
wat2wasm_OBJECTS = \
"CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o"

# External object files for target wat2wasm
wat2wasm_EXTERNAL_OBJECTS =

wat2wasm: CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o
wat2wasm: CMakeFiles/wat2wasm.dir/build.make
wat2wasm: libwabt.a
wat2wasm: CMakeFiles/wat2wasm.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable wat2wasm"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/wat2wasm.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/wat2wasm.dir/build: wat2wasm

.PHONY : CMakeFiles/wat2wasm.dir/build

CMakeFiles/wat2wasm.dir/requires: CMakeFiles/wat2wasm.dir/src/tools/wat2wasm.cc.o.requires

.PHONY : CMakeFiles/wat2wasm.dir/requires

CMakeFiles/wat2wasm.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/wat2wasm.dir/cmake_clean.cmake
.PHONY : CMakeFiles/wat2wasm.dir/clean

CMakeFiles/wat2wasm.dir/depend:
	cd /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles/wat2wasm.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/wat2wasm.dir/depend

