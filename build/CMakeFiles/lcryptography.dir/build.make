# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.18

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/rujas/code_workspace/enigma4/cryptography

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/rujas/code_workspace/enigma4/cryptography/build

# Include any dependencies generated for this target.
include CMakeFiles/lcryptography.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/lcryptography.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/lcryptography.dir/flags.make

CMakeFiles/lcryptography.dir/src/aes.cc.o: CMakeFiles/lcryptography.dir/flags.make
CMakeFiles/lcryptography.dir/src/aes.cc.o: ../src/aes.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rujas/code_workspace/enigma4/cryptography/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/lcryptography.dir/src/aes.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/lcryptography.dir/src/aes.cc.o -c /home/rujas/code_workspace/enigma4/cryptography/src/aes.cc

CMakeFiles/lcryptography.dir/src/aes.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lcryptography.dir/src/aes.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rujas/code_workspace/enigma4/cryptography/src/aes.cc > CMakeFiles/lcryptography.dir/src/aes.cc.i

CMakeFiles/lcryptography.dir/src/aes.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lcryptography.dir/src/aes.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rujas/code_workspace/enigma4/cryptography/src/aes.cc -o CMakeFiles/lcryptography.dir/src/aes.cc.s

CMakeFiles/lcryptography.dir/src/rsa.cc.o: CMakeFiles/lcryptography.dir/flags.make
CMakeFiles/lcryptography.dir/src/rsa.cc.o: ../src/rsa.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rujas/code_workspace/enigma4/cryptography/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/lcryptography.dir/src/rsa.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/lcryptography.dir/src/rsa.cc.o -c /home/rujas/code_workspace/enigma4/cryptography/src/rsa.cc

CMakeFiles/lcryptography.dir/src/rsa.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lcryptography.dir/src/rsa.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rujas/code_workspace/enigma4/cryptography/src/rsa.cc > CMakeFiles/lcryptography.dir/src/rsa.cc.i

CMakeFiles/lcryptography.dir/src/rsa.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lcryptography.dir/src/rsa.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rujas/code_workspace/enigma4/cryptography/src/rsa.cc -o CMakeFiles/lcryptography.dir/src/rsa.cc.s

CMakeFiles/lcryptography.dir/src/base64.cc.o: CMakeFiles/lcryptography.dir/flags.make
CMakeFiles/lcryptography.dir/src/base64.cc.o: ../src/base64.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rujas/code_workspace/enigma4/cryptography/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/lcryptography.dir/src/base64.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/lcryptography.dir/src/base64.cc.o -c /home/rujas/code_workspace/enigma4/cryptography/src/base64.cc

CMakeFiles/lcryptography.dir/src/base64.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lcryptography.dir/src/base64.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rujas/code_workspace/enigma4/cryptography/src/base64.cc > CMakeFiles/lcryptography.dir/src/base64.cc.i

CMakeFiles/lcryptography.dir/src/base64.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lcryptography.dir/src/base64.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rujas/code_workspace/enigma4/cryptography/src/base64.cc -o CMakeFiles/lcryptography.dir/src/base64.cc.s

# Object files for target lcryptography
lcryptography_OBJECTS = \
"CMakeFiles/lcryptography.dir/src/aes.cc.o" \
"CMakeFiles/lcryptography.dir/src/rsa.cc.o" \
"CMakeFiles/lcryptography.dir/src/base64.cc.o"

# External object files for target lcryptography
lcryptography_EXTERNAL_OBJECTS =

liblcryptography.a: CMakeFiles/lcryptography.dir/src/aes.cc.o
liblcryptography.a: CMakeFiles/lcryptography.dir/src/rsa.cc.o
liblcryptography.a: CMakeFiles/lcryptography.dir/src/base64.cc.o
liblcryptography.a: CMakeFiles/lcryptography.dir/build.make
liblcryptography.a: CMakeFiles/lcryptography.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/rujas/code_workspace/enigma4/cryptography/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX static library liblcryptography.a"
	$(CMAKE_COMMAND) -P CMakeFiles/lcryptography.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lcryptography.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/lcryptography.dir/build: liblcryptography.a

.PHONY : CMakeFiles/lcryptography.dir/build

CMakeFiles/lcryptography.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/lcryptography.dir/cmake_clean.cmake
.PHONY : CMakeFiles/lcryptography.dir/clean

CMakeFiles/lcryptography.dir/depend:
	cd /home/rujas/code_workspace/enigma4/cryptography/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rujas/code_workspace/enigma4/cryptography /home/rujas/code_workspace/enigma4/cryptography /home/rujas/code_workspace/enigma4/cryptography/build /home/rujas/code_workspace/enigma4/cryptography/build /home/rujas/code_workspace/enigma4/cryptography/build/CMakeFiles/lcryptography.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/lcryptography.dir/depend
