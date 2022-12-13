# Welcome to the Inject DLL project

## OVERVIEW

This is a sample project that demonstrates how to inject a DLL into a process and then intercept / alter the behavior of APIs. 

## BUILDING

Building Inject DLL requires the latest version of Visual Studio (currently, VS2022) and a handful of libraries to compile the code.

### Libraries Required

The .vcproj files expect there to be an environment variable, named 'Local_IncludePath', that contains the headers for the libraries it is dependent on. 
All dependent libraries are located on GitHub. It is typically easiest to clone those repositories and create a symlink to the proper directory in the cloned repo.

The dependencies are as follows:

`Local_IncludePath` - Environment variable that points to a directory with the following subdirectories in it:

	boost - Symlink to github.com/boostorg/boost/boost (note, you need to build the headers by running `bootstrap.bat && .\b2 headers` after cloning the repo.)
	detours - Symlink to github.com/microsoft/detours (note, you also need to build detours using `nmake` in the approriate VS buid environment, e.g. x64)
	dumbnose - Symlink to github.com/dumbnose/dumbnose/lib/dumbnose

