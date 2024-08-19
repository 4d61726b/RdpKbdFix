mkdir Bundles

mkdir Bundles\ReleaseBundle
copy Build\Win32\Release\RdpKbdFix32.dll Bundles\ReleaseBundle\
copy Build\x64\Release\RdpKbdFix64.dll Bundles\ReleaseBundle\

mkdir Bundles\DebugBundle
copy Build\Win32\Debug\RdpKbdFix32.dll Bundles\DebugBundle\
copy Build\x64\Debug\RdpKbdFix64.dll Bundles\DebugBundle\
