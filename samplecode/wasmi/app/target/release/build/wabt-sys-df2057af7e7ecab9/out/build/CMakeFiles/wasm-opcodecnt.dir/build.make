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
include CMakeFiles/wasm-opcodecnt.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/wasm-opcodecnt.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/wasm-opcodecnt.dir/flags.make

CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o: CMakeFiles/wasm-opcodecnt.dir/flags.make
CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o: /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wasm-opcodecnt.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o -c /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wasm-opcodecnt.cc

CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wasm-opcodecnt.cc > CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.i

CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/tools/wasm-opcodecnt.cc -o CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.s

CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o.requires:

.PHONY : CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o.requires

CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o.provides: CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o.requires
	$(MAKE) -f CMakeFiles/wasm-opcodecnt.dir/build.make CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o.provides.build
.PHONY : CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o.provides

CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o.provides.build: CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o


CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o: CMakeFiles/wasm-opcodecnt.dir/flags.make
CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o: /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/binary-reader-opcnt.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o -c /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/binary-reader-opcnt.cc

CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/binary-reader-opcnt.cc > CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.i

CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt/src/binary-reader-opcnt.cc -o CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.s

CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o.requires:

.PHONY : CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o.requires

CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o.provides: CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o.requires
	$(MAKE) -f CMakeFiles/wasm-opcodecnt.dir/build.make CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o.provides.build
.PHONY : CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o.provides

CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o.provides.build: CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o


# Object files for target wasm-opcodecnt
wasm__opcodecnt_OBJECTS = \
"CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o" \
"CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o"

# External object files for target wasm-opcodecnt
wasm__opcodecnt_EXTERNAL_OBJECTS =

wasm-opcodecnt: CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o
wasm-opcodecnt: CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o
wasm-opcodecnt: CMakeFiles/wasm-opcodecnt.dir/build.make
wasm-opcodecnt: libwabt.a
wasm-opcodecnt: CMakeFiles/wasm-opcodecnt.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable wasm-opcodecnt"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/wasm-opcodecnt.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/wasm-opcodecnt.dir/build: wasm-opcodecnt

.PHONY : CMakeFiles/wasm-opcodecnt.dir/build

CMakeFiles/wasm-opcodecnt.dir/requires: CMakeFiles/wasm-opcodecnt.dir/src/tools/wasm-opcodecnt.cc.o.requires
CMakeFiles/wasm-opcodecnt.dir/requires: CMakeFiles/wasm-opcodecnt.dir/src/binary-reader-opcnt.cc.o.requires

.PHONY : CMakeFiles/wasm-opcodecnt.dir/requires

CMakeFiles/wasm-opcodecnt.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/wasm-opcodecnt.dir/cmake_clean.cmake
.PHONY : CMakeFiles/wasm-opcodecnt.dir/clean

CMakeFiles/wasm-opcodecnt.dir/depend:
	cd /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/.cargo/registry/src/github.com-1ecc6299db9ec823/wabt-sys-0.2.0/wabt /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build /root/sgx/samplecode/wasmi/app/target/release/build/wabt-sys-df2057af7e7ecab9/out/build/CMakeFiles/wasm-opcodecnt.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/wasm-opcodecnt.dir/depend

