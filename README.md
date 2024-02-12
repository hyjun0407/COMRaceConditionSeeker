# What is ComRaceConditionSeeker?
The Component Object Model (COM) is a software architecture developed by Microsoft that enables various software components to communicate and exchange data with each other. It is widely used in the Windows operating system and enables developers to build applications from modular components. COM is designed to be language-independent, which means that components written in different programming languages can interact with each other.

The key concepts of COM are based on the principles of object-oriented programming, which promote the reusability and maintainability of software components through the separation of interface and implementation. COM objects can only be accessed through defined interfaces, which are identified by a unique identifier, the Global Unique Identifier (GUID).

COM technology is leveraged in many areas of Windows programming. For example, Object Linking and Embedding (OLE) and ActiveX controls are based on COM, which enables features such as embedding in documents and dynamic content delivery in applications such as Internet Explorer.

COM is also the foundation for the Distributed Component Object Model (DCOM), which enables communication between components over a network. This allows developers to realize the sharing of data and services among applications running on different computers on a network.

ComRaceConditionSeeker helps you quickly screen these COMs for candidate functions that can be Race-Conditioned. If you look at the Patch Diff of most Race-Conditions, you will see that they have atomic locks (e.g. SRWLock, CrticalSection, etc.) at the beginning and end of the function to allow them to run synchronously.

Therefore, ComRaceConditionSeeker (henceforth CRSeeker) is designed to find candidate functions in the DLL where the actual implementation of COM takes place.
candidate functions that do not have a lock, and identifies the shared resources referenced by those functions ('this' object with the same structure), so that the user can find the function with the faster race condition potential.

We can Reproduce CVE-2020-1394/1146/1211 successfully with ComRaceConditionSeeker, and I am glad to find new race-conditionable function with ComRaceConditionSeeker.

# How-To-Use
Simple. Just execute this script on IDA
just check what "LOCK" related Function that target binary using and add it to banlist if there aren't exist.

# Example Output
```python
Category: Windows::System::UserStatics *
  - ['?GetNonRoamableIdForUserAndApp@UserStatics@System@Windows@@UEAAJPEAUIUser@23@PEAUHSTRING__@@PEAPEAU5@@Z', 6442468736, [18, 72, 144], 'Windows::System::UserStatics *']
  - ['?RemoveUserAndFireUserRemoved@UserStatics@System@Windows@@UEAAJII@Z', 6442492416, [6, 14, 18, 20, 27, 35, 44, 72, 88, 112, 144, 160, 176, 216, 240, 280, 296, 360, 384], 'Windows::System::UserStatics *']
  - ['?GetUserById@UserStatics@System@Windows@@UEAAJIIPEAPEAUIUser@23@@Z', 6442494496, [14, 16, 72, 112, 128], 'Windows::System::UserStatics *']
  - ['?ChangeSessionActiveShellUser@UserStatics@System@Windows@@UEAAJII@Z', 6442496944, [56], 'Windows::System::UserStatics *']
  - ['?GetSessionActiveShellUser@UserStatics@System@Windows@@UEAAJIPEAPEAUIUser@23@@Z', 6442510688, [27, 176, 216], 'Windows::System::UserStatics *']
  - ['?CreateInternalWatcher@UserStatics@System@Windows@@UEAAJPEAPEAUIUserWatcher@23@@Z', 6442518672, [312, 384], 'Windows::System::UserStatics *']
  - ['?RemoveSessionActiveShellUser@UserStatics@System@Windows@@UEAAJI@Z', 6442587520, [176, 216], 'Windows::System::UserStatics *']
  - ['??1UserStatics@System@Windows@@UEAA@XZ', 6442948672, [1, 4, 5, 6, 7, 21, 23, 25, 27, 34, 42, 44, 51, 52, 53, 54, 55, 56, 57, 128, 168, 184, 200, 216, 232, 296, 336, 352, 368], 'Windows::System::UserStatics *']
  - ['?CreateWatcher@UserStatics@System@Windows@@UEAAJPEAPEAUIUserWatcher@23@@Z', 6442958384, [328, 376], 'Windows::System::UserStatics *']
  - ['?FireSignOutStarted@UserStatics@System@Windows@@UEAAJPEAUIUser@23@EPEAPEAUIUserAuthenticationStatusChangingEventArgs@23@@Z', 6442965184, [45, 46, 48, 49, 312, 360, 384], 'Windows::System::UserStatics *']
  - ['?RemovePartialUserAndFireUserRemoved@UserStatics@System@Windows@@UEAAJII@Z', 6442978240, [16, 20, 44, 72, 160, 384], 'Windows::System::UserStatics *']
  - ['?TryFindUser@UserStatics@System@Windows@@UEAAJIIPEAEPEAPEAUIUser@23@@Z', 6442981648, [14, 16, 72], 'Windows::System::UserStatics *']
  - ['?TryFindUserByContextWithCache@UserStatics@System@Windows@@UEAAJ_KPEAPEAUIUser@23@@Z', 6442982848, [20, 72, 160], 'Windows::System::UserStatics *']

.
.
.
Category: Windows::System::UserAuthenticationStatusChangingEventArgs *
  - ['?GetDeferral@UserAuthenticationStatusChangingEventArgs@System@Windows@@UEAAJPEAPEAUIUserAuthenticationStatusChangeDeferral@23@@Z', 6443400416, [2, 15, 80], 'Windows::System::UserAuthenticationStatusChangingEventArgs *']

Category: Windows::System::Internal::SignInContext *
  - ['**?get_AuthData@SignInContext@Internal@System@Windows@@UEAAJPEAPEAUHSTRING__@@@Z**', 6443452176, [10, 15, 80], 'Windows::System::Internal::SignInContext *']
  - ['?get_CorrelationId@SignInContext@Internal@System@Windows@@UEAAJPEAPEAUHSTRING__@@@Z', 6443452384, [8, 16, 64], 'Windows::System::Internal::SignInContext *']
  - ['?get_Credentials@SignInContext@Internal@System@Windows@@UEAAJPEAPEAUICredentialSerialization@234@@Z', 6443452592, [10, 16, 80], 'Windows::System::Internal::SignInContext *']
  - ['?put_AuthData@SignInContext@Internal@System@Windows@@UEAAJPEAUHSTRING__@@@Z', 6443453216, [10, 15, 80], 'Windows::System::Internal::SignInContext *']
  - ['?put_CorrelationId@SignInContext@Internal@System@Windows@@UEAAJPEAUHSTRING__@@@Z', 6443453376, [8, 16, 64], 'Windows::System::Internal::SignInContext *']
  - ['?put_Properties@SignInContext@Internal@System@Windows@@UEAAJPEAUIPropertySet@Collections@Foundation@4@@Z', 6443453680, [10, 17], 'Windows::System::Internal::SignInContext *']

Category: WsiEnvironmentAccountManagerTraceProvider::FunctionCall *
  - ['?StartActivity@FunctionCall@WsiEnvironmentAccountManagerTraceProvider@@QEAAXXZ', 6443602172, [6, 8], 'WsiEnvironmentAccountManagerTraceProvider::FunctionCall *']

Category: CredProvUtils *
  - ['?GetLogonUIKeyPath@CredProvUtils@@YAJPEAPEAG@Z', 6443608696, [], 'CredProvUtils *']
```
