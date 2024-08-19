SET VS170COMNTOOLS=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools
call "%VS170COMNTOOLS%\..\..\VC\Auxiliary\Build\vcvarsall.bat" x64
echo on

msbuild /m RdpKbdFix.sln /property:Platform=x86 /property:Configuration="Debug" || goto error
msbuild /m RdpKbdFix.sln /property:Platform=x64 /property:Configuration="Debug" || goto error
msbuild /m RdpKbdFix.sln /property:Platform=x86 /property:Configuration="Release" || goto error
msbuild /m RdpKbdFix.sln /property:Platform=x64 /property:Configuration="Release" || goto error

goto success

:error
echo Build failed!
goto end

:success
call "createbundles.bat"

:end
pause

