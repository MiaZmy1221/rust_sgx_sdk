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
include CMakeFiles/wast2json.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/wast2json.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/wast2json.dir/flags.make

CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o: CMakeFiles/wast2json.dir/flags.make
CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o: /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wast2json.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o -c /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wast2json.cc

CMakeFiles/wast2json.dir/src/tools/wast2json.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/wast2json.dir/src/tools/wast2json.cc.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wast2json.cc > CMakeFiles/wast2json.dir/src/tools/wast2json.cc.i

CMakeFiles/wast2json.dir/src/tools/wast2json.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/wast2json.dir/src/tools/wast2json.cc.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wast2json.cc -o CMakeFiles/wast2json.dir/src/tools/wast2json.cc.s

CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o.requires:

.PHONY : CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o.requires

CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o.provides: CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o.requires
	$(MAKE) -f CMakeFiles/wast2json.dir/build.make CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o.provides.build
.PHONY : CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o.provides

CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o.provides.build: CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o


# Object files for target wast2json
wast2json_OBJECTS = \
"CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o"

# External object files for target wast2json
wast2json_EXTERNAL_OBJECTS =

wast2json: CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o
wast2json: CMakeFiles/wast2json.dir/build.make
wast2json: libwabt.a
wast2json: CMakeFiles/wast2json.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable wast2json"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/wast2json.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/wast2json.dir/build: wast2json

.PHONY : CMakeFiles/wast2json.dir/build

CMakeFiles/wast2json.dir/requires: CMakeFiles/wast2json.dir/src/tools/wast2json.cc.o.requires

.PHONY : CMakeFiles/wast2json.dir/requires

CMakeFiles/wast2json.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/wast2json.dir/cmake_clean.cmake
.PHONY : CMakeFiles/wast2json.dir/clean

CMakeFiles/wast2json.dir/depend:
	cd /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles/wast2json.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/wast2json.dir/depend

