@echo off
echo Building RoboCopyGui distribution...

REM Clean up any existing distribution folders
if exist robocopygui.dist (
    echo Cleaning existing distribution folder robocopygui.dist...
    del robocopygui.dist\* /Q
)

REM Build the standalone executable with Nuitka
echo Building executable with Nuitka...
call nuitka --windows-icon-from-ico=appicon.ico --windows-console-mode=disable --standalone --enable-plugin=tk-inter robocopygui.py

REM Copy configuration and resource files
echo Copying configuration and resource files...
robocopy ./ ./robocopygui.dist appicon.png config.json gui.json labels.json LICENSE README.md

echo Distribution build complete!
echo Files are available in the robocopygui.dist directory.