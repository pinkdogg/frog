# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_SOURCE_DIR = /home/lighthouse/workspace/sgx/frog

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lighthouse/workspace/sgx/frog/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/client.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/client.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/client.dir/flags.make

CMakeFiles/client.dir/src/app/client.cc.o: CMakeFiles/client.dir/flags.make
CMakeFiles/client.dir/src/app/client.cc.o: ../src/app/client.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lighthouse/workspace/sgx/frog/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/client.dir/src/app/client.cc.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/client.dir/src/app/client.cc.o -c /home/lighthouse/workspace/sgx/frog/src/app/client.cc

CMakeFiles/client.dir/src/app/client.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/client.dir/src/app/client.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lighthouse/workspace/sgx/frog/src/app/client.cc > CMakeFiles/client.dir/src/app/client.cc.i

CMakeFiles/client.dir/src/app/client.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/client.dir/src/app/client.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lighthouse/workspace/sgx/frog/src/app/client.cc -o CMakeFiles/client.dir/src/app/client.cc.s

CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.o: CMakeFiles/client.dir/flags.make
CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.o: ../src/comm/CryptoPrimitive.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lighthouse/workspace/sgx/frog/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.o -c /home/lighthouse/workspace/sgx/frog/src/comm/CryptoPrimitive.cc

CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lighthouse/workspace/sgx/frog/src/comm/CryptoPrimitive.cc > CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.i

CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lighthouse/workspace/sgx/frog/src/comm/CryptoPrimitive.cc -o CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.s

CMakeFiles/client.dir/src/comm/SSLConnection.cc.o: CMakeFiles/client.dir/flags.make
CMakeFiles/client.dir/src/comm/SSLConnection.cc.o: ../src/comm/SSLConnection.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lighthouse/workspace/sgx/frog/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/client.dir/src/comm/SSLConnection.cc.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/client.dir/src/comm/SSLConnection.cc.o -c /home/lighthouse/workspace/sgx/frog/src/comm/SSLConnection.cc

CMakeFiles/client.dir/src/comm/SSLConnection.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/client.dir/src/comm/SSLConnection.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lighthouse/workspace/sgx/frog/src/comm/SSLConnection.cc > CMakeFiles/client.dir/src/comm/SSLConnection.cc.i

CMakeFiles/client.dir/src/comm/SSLConnection.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/client.dir/src/comm/SSLConnection.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lighthouse/workspace/sgx/frog/src/comm/SSLConnection.cc -o CMakeFiles/client.dir/src/comm/SSLConnection.cc.s

CMakeFiles/client.dir/src/client/FileSender.cc.o: CMakeFiles/client.dir/flags.make
CMakeFiles/client.dir/src/client/FileSender.cc.o: ../src/client/FileSender.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lighthouse/workspace/sgx/frog/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/client.dir/src/client/FileSender.cc.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/client.dir/src/client/FileSender.cc.o -c /home/lighthouse/workspace/sgx/frog/src/client/FileSender.cc

CMakeFiles/client.dir/src/client/FileSender.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/client.dir/src/client/FileSender.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lighthouse/workspace/sgx/frog/src/client/FileSender.cc > CMakeFiles/client.dir/src/client/FileSender.cc.i

CMakeFiles/client.dir/src/client/FileSender.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/client.dir/src/client/FileSender.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lighthouse/workspace/sgx/frog/src/client/FileSender.cc -o CMakeFiles/client.dir/src/client/FileSender.cc.s

CMakeFiles/client.dir/src/client/OrderSender.cc.o: CMakeFiles/client.dir/flags.make
CMakeFiles/client.dir/src/client/OrderSender.cc.o: ../src/client/OrderSender.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lighthouse/workspace/sgx/frog/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/client.dir/src/client/OrderSender.cc.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/client.dir/src/client/OrderSender.cc.o -c /home/lighthouse/workspace/sgx/frog/src/client/OrderSender.cc

CMakeFiles/client.dir/src/client/OrderSender.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/client.dir/src/client/OrderSender.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lighthouse/workspace/sgx/frog/src/client/OrderSender.cc > CMakeFiles/client.dir/src/client/OrderSender.cc.i

CMakeFiles/client.dir/src/client/OrderSender.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/client.dir/src/client/OrderSender.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lighthouse/workspace/sgx/frog/src/client/OrderSender.cc -o CMakeFiles/client.dir/src/client/OrderSender.cc.s

CMakeFiles/client.dir/src/comm/json11.cc.o: CMakeFiles/client.dir/flags.make
CMakeFiles/client.dir/src/comm/json11.cc.o: ../src/comm/json11.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lighthouse/workspace/sgx/frog/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/client.dir/src/comm/json11.cc.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/client.dir/src/comm/json11.cc.o -c /home/lighthouse/workspace/sgx/frog/src/comm/json11.cc

CMakeFiles/client.dir/src/comm/json11.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/client.dir/src/comm/json11.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lighthouse/workspace/sgx/frog/src/comm/json11.cc > CMakeFiles/client.dir/src/comm/json11.cc.i

CMakeFiles/client.dir/src/comm/json11.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/client.dir/src/comm/json11.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lighthouse/workspace/sgx/frog/src/comm/json11.cc -o CMakeFiles/client.dir/src/comm/json11.cc.s

# Object files for target client
client_OBJECTS = \
"CMakeFiles/client.dir/src/app/client.cc.o" \
"CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.o" \
"CMakeFiles/client.dir/src/comm/SSLConnection.cc.o" \
"CMakeFiles/client.dir/src/client/FileSender.cc.o" \
"CMakeFiles/client.dir/src/client/OrderSender.cc.o" \
"CMakeFiles/client.dir/src/comm/json11.cc.o"

# External object files for target client
client_EXTERNAL_OBJECTS =

../bin/client: CMakeFiles/client.dir/src/app/client.cc.o
../bin/client: CMakeFiles/client.dir/src/comm/CryptoPrimitive.cc.o
../bin/client: CMakeFiles/client.dir/src/comm/SSLConnection.cc.o
../bin/client: CMakeFiles/client.dir/src/client/FileSender.cc.o
../bin/client: CMakeFiles/client.dir/src/client/OrderSender.cc.o
../bin/client: CMakeFiles/client.dir/src/comm/json11.cc.o
../bin/client: CMakeFiles/client.dir/build.make
../bin/client: /usr/lib/x86_64-linux-gnu/libssl.so
../bin/client: /usr/lib/x86_64-linux-gnu/libcrypto.so
../bin/client: CMakeFiles/client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lighthouse/workspace/sgx/frog/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking CXX executable ../bin/client"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/client.dir/build: ../bin/client

.PHONY : CMakeFiles/client.dir/build

CMakeFiles/client.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/client.dir/cmake_clean.cmake
.PHONY : CMakeFiles/client.dir/clean

CMakeFiles/client.dir/depend:
	cd /home/lighthouse/workspace/sgx/frog/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lighthouse/workspace/sgx/frog /home/lighthouse/workspace/sgx/frog /home/lighthouse/workspace/sgx/frog/cmake-build-debug /home/lighthouse/workspace/sgx/frog/cmake-build-debug /home/lighthouse/workspace/sgx/frog/cmake-build-debug/CMakeFiles/client.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/client.dir/depend
