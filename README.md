# RdpKbdFix (Remote Desktop Keyboard Fix)

## What is RdpKbdFix?

RdpKbdFix is a tool that assists with Remote Desktop input compatibility for software products running on 64-bit Windows.

Products such as VMware Workstation or VMware Remote Console do not currently handle Unicode input properly. As of this writing, both these products only support input keystrokes as scancode. This results in no keyboard input when accessing these products via the Remote Desktop application on your phone or tablet.

Microsoft Remote Desktop for Android has an option in "General Settings" to "Use scancode input when available". This feature is only present on Android and doesn't always work. Additionally, this is not currently a supported feature on iOS / iPadOS.

This tool specifically fixes the shortcomings of legacy software or various VMware products not being able to handle Unicode input. The end result is successful keyboard input when using the Microsoft Remote Desktop apps for Android and iOS.

## How does RdpKbdFix work?

Products such as VMware Workstation or VMware Remote Console do not currently handle Unicode based `VK_PACKET` keyboard events that are sent by the Remote Desktop client for Android and iOS when a keyboard key is pressed.

RdpKbdFix temporarily installs a low level keyboard hook to attempt to translate keystrokes. This results in basic keyboard functionality for US based keyboards.

## Documentation

### Intro

There are two DLLs:

* RdpKbdFix32.dll - This is needed for fixing the VMware Remote Console application
* RdpKbdFix64.dll - This is needed for fixing the VMware Workstation application

Both can be used simultaneously, but only one instance of each variant is necessary.

There are two modes. The first mode (`Run`), will install hooks only for VMware products.

The second mode `Run2`, will perform the same operation as `Run` but will also install hooks globally (for all applications). `Run2` is also known as "Global hook mode". This is useful for fixing issues when using the "VMware Web Console" within your web browser instead of the standalone VMware Remote Console application (i.e. `vmrc.exe`).

To remove the hook(s), exit both the `rundll32.exe` process as well as VMware processes that were successfully injected into.

### Usage Examples

To fix the VMware Remote Console application:
```batch
C:\Windows\SysWOW64\rundll32.exe RdpKbdFix32.dll, Run
```

OR (to also enable global mode):

```batch
C:\Windows\SysWOW64\rundll32.exe RdpKbdFix32.dll, Run2
```

To fix the VMware Workstation application:
```batch
C:\Windows\System32\rundll32.exe RdpKbdFix64.dll, Run
```

OR (to also enable global mode):

```batch
C:\Windows\System32\rundll32.exe RdpKbdFix64.dll, Run2
```

## Downloads
[Download the latest RdpKbdFix release](https://github.com/4d61726b/RdpKbdFix/releases)

## Build Instructions
### Prerequisites
* Visual Studio 2022
### Steps
2. Edit make.bat to modify VS170COMNTOOLS path if needed
3. Run make.bat
4. Use binaries produced in Bundle directory
## Issues or Feature Requests
* Issues, bugs, or feature requests can be raised on the [issue tracker on GitHub](https://github.com/4d61726b/RdpKbdFix/issues).
