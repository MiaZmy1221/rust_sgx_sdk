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
include CMakeFiles/spectest-interp.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/spectest-interp.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/spectest-interp.dir/flags.make

CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o: CMakeFiles/spectest-interp.dir/flags.make
CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o: /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/spectest-interp.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o -c /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/spectest-interp.cc

CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/spectest-interp.cc > CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.i

CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/spectest-interp.cc -o CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.s

CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o.requires:

.PHONY : CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o.requires

CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o.provides: CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o.requires
	$(MAKE) -f CMakeFiles/spectest-interp.dir/build.make CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o.provides.build
.PHONY : CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o.provides

CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o.provides.build: CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o


# Object files for target spectest-interp
spectest__interp_OBJECTS = \
"CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o"

# External object files for target spectest-interp
spectest__interp_EXTERNAL_OBJECTS =

spectest-interp: CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o
spectest-interp: CMakeFiles/spectest-interp.dir/build.make
spectest-interp: libwabt.a
spectest-interp: CMakeFiles/spectest-interp.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable spectest-interp"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/spectest-interp.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/spectest-interp.dir/build: spectest-interp

.PHONY : CMakeFiles/spectest-interp.dir/build

CMakeFiles/spectest-interp.dir/requires: CMakeFiles/spectest-interp.dir/src/tools/spectest-interp.cc.o.requires

.PHONY : CMakeFiles/spectest-interp.dir/requires

CMakeFiles/spectest-interp.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/spectest-interp.dir/cmake_clean.cmake
.PHONY : CMakeFiles/spectest-interp.dir/clean

CMakeFiles/spectest-interp.dir/depend:
	cd /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/enclave/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles/spectest-interp.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/spectest-interp.dir/depend

