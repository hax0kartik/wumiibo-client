# CMAKE generated file: DO NOT EDIT!
# Generated by "MSYS Makefiles" Generator, CMake Version 3.17

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


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
CMAKE_COMMAND = /C/msys64/mingw64/bin/cmake.exe

# The command to remove a file.
RM = /C/msys64/mingw64/bin/cmake.exe -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /C/Users/Kartik/Desktop/pro_kartik/nfc-rewrite/wumiibo-client

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /C/Users/Kartik/Desktop/pro_kartik/nfc-rewrite/wumiibo-client

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/C/msys64/mingw64/bin/cmake.exe --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/C/msys64/mingw64/bin/cmake-gui.exe -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /C/Users/Kartik/Desktop/pro_kartik/nfc-rewrite/wumiibo-client/CMakeFiles /C/Users/Kartik/Desktop/pro_kartik/nfc-rewrite/wumiibo-client/CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /C/Users/Kartik/Desktop/pro_kartik/nfc-rewrite/wumiibo-client/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named Wumiibo

# Build rule for target.
Wumiibo: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 Wumiibo
.PHONY : Wumiibo

# fast build rule for target.
Wumiibo/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/build
.PHONY : Wumiibo/fast

source/AmiiboUtil.obj: source/AmiiboUtil.cpp.obj

.PHONY : source/AmiiboUtil.obj

# target to build an object file
source/AmiiboUtil.cpp.obj:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/AmiiboUtil.cpp.obj
.PHONY : source/AmiiboUtil.cpp.obj

source/AmiiboUtil.i: source/AmiiboUtil.cpp.i

.PHONY : source/AmiiboUtil.i

# target to preprocess a source file
source/AmiiboUtil.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/AmiiboUtil.cpp.i
.PHONY : source/AmiiboUtil.cpp.i

source/AmiiboUtil.s: source/AmiiboUtil.cpp.s

.PHONY : source/AmiiboUtil.s

# target to generate assembly for a file
source/AmiiboUtil.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/AmiiboUtil.cpp.s
.PHONY : source/AmiiboUtil.cpp.s

source/communicator.obj: source/communicator.cpp.obj

.PHONY : source/communicator.obj

# target to build an object file
source/communicator.cpp.obj:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/communicator.cpp.obj
.PHONY : source/communicator.cpp.obj

source/communicator.i: source/communicator.cpp.i

.PHONY : source/communicator.i

# target to preprocess a source file
source/communicator.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/communicator.cpp.i
.PHONY : source/communicator.cpp.i

source/communicator.s: source/communicator.cpp.s

.PHONY : source/communicator.s

# target to generate assembly for a file
source/communicator.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/communicator.cpp.s
.PHONY : source/communicator.cpp.s

source/main.obj: source/main.cpp.obj

.PHONY : source/main.obj

# target to build an object file
source/main.cpp.obj:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/main.cpp.obj
.PHONY : source/main.cpp.obj

source/main.i: source/main.cpp.i

.PHONY : source/main.i

# target to preprocess a source file
source/main.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/main.cpp.i
.PHONY : source/main.cpp.i

source/main.s: source/main.cpp.s

.PHONY : source/main.s

# target to generate assembly for a file
source/main.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Wumiibo.dir/build.make CMakeFiles/Wumiibo.dir/source/main.cpp.s
.PHONY : source/main.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... Wumiibo"
	@echo "... source/AmiiboUtil.obj"
	@echo "... source/AmiiboUtil.i"
	@echo "... source/AmiiboUtil.s"
	@echo "... source/communicator.obj"
	@echo "... source/communicator.i"
	@echo "... source/communicator.s"
	@echo "... source/main.obj"
	@echo "... source/main.i"
	@echo "... source/main.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

