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
CMAKE_BINARY_DIR = /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build

# Include any dependencies generated for this target.
include CMakeFiles/wasm-interp.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/wasm-interp.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/wasm-interp.dir/flags.make

CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o: CMakeFiles/wasm-interp.dir/flags.make
CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o: /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wasm-interp.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o -c /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wasm-interp.cc

CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wasm-interp.cc > CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.i

CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wasm-interp.cc -o CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.s

CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o.requires:

.PHONY : CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o.requires

CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o.provides: CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o.requires
	$(MAKE) -f CMakeFiles/wasm-interp.dir/build.make CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o.provides.build
.PHONY : CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o.provides

CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o.provides.build: CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o


# Object files for target wasm-interp
wasm__interp_OBJECTS = \
"CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o"

# External object files for target wasm-interp
wasm__interp_EXTERNAL_OBJECTS =

wasm-interp: CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o
wasm-interp: CMakeFiles/wasm-interp.dir/build.make
wasm-interp: libwabt.a
wasm-interp: CMakeFiles/wasm-interp.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable wasm-interp"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/wasm-interp.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/wasm-interp.dir/build: wasm-interp

.PHONY : CMakeFiles/wasm-interp.dir/build

CMakeFiles/wasm-interp.dir/requires: CMakeFiles/wasm-interp.dir/src/tools/wasm-interp.cc.o.requires

.PHONY : CMakeFiles/wasm-interp.dir/requires

CMakeFiles/wasm-interp.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/wasm-interp.dir/cmake_clean.cmake
.PHONY : CMakeFiles/wasm-interp.dir/clean

CMakeFiles/wasm-interp.dir/depend:
	cd /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles/wasm-interp.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/wasm-interp.dir/depend

