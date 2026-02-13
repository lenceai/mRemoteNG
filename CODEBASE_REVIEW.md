# mRemoteNG Codebase Review & Improvement Recommendations

**Reviewed:** February 2026  
**Scope:** Full codebase review of mRemoteNG v1.78.2-dev (~760 C# source files)

---

## Table of Contents

1. [Critical Security Issues](#1-critical-security-issues)
2. [Architecture & Design Improvements](#2-architecture--design-improvements)
3. [Code Quality & Maintainability](#3-code-quality--maintainability)
4. [Error Handling & Reliability](#4-error-handling--reliability)
5. [Performance Improvements](#5-performance-improvements)
6. [Testing Gaps](#6-testing-gaps)
7. [Dependency & Build Improvements](#7-dependency--build-improvements)
8. [Protocol-Specific Issues](#8-protocol-specific-issues)
9. [Configuration & Serialization](#9-configuration--serialization)
10. [UI/UX Improvements](#10-uiux-improvements)

---

## 1. Critical Security Issues

### 1.1 Passwords Stored as Plain Strings in Memory

**Severity:** HIGH  
**Location:** `Connection/AbstractConnectionRecord.cs` (line 38)

The `Password` field was changed from `SecureString` to plain `string`:

```csharp
//private SecureString _password = null;
private string _password = null;
```

This means passwords reside in managed memory as plain `System.String` objects, which are immutable and cannot be zeroed. They may persist in memory long after use and are visible in memory dumps. The commented-out `SecureString` versions throughout the codebase (e.g., in `RdpProtocol.cs` line 567-568, `PuttyBase.cs` line 111-112) suggest this was a deliberate regression, likely for convenience.

**Recommendation:** Restore `SecureString` usage for password fields. If the API boundaries make this difficult, implement a wrapper that stores encrypted bytes and only decrypts them briefly when needed (similar to the existing `EncryptedSecureString` class, which is underutilized).

### 1.2 Legacy Rijndael Provider Uses MD5 for Key Derivation

**Severity:** HIGH  
**Location:** `Security/SymmetricEncryption/LegacyRijndaelCryptographyProvider.cs` (lines 39-43)

The legacy crypto provider uses MD5 to derive AES keys from passwords:

```csharp
using (MD5 md5 = MD5.Create())
{
    byte[] key = md5.ComputeHash(Encoding.UTF8.GetBytes(strSecret.ConvertToUnsecureString()));
    aes.Key = key;
}
```

MD5 is cryptographically broken and produces only a 128-bit key, while AES-256 should be used. This provider is still actively used in `SqlConnectionsLoader`, `SqlConnectionsSaver`, `PuttyBase`, and `RdpProtocol` for default credential handling.

**Recommendation:** Create a migration path to replace `LegacyRijndaelCryptographyProvider` with `AeadCryptographyProvider` everywhere. Mark the legacy provider with `[Obsolete]` and add a one-time migration on startup to re-encrypt data using the modern provider.

### 1.3 Low PBKDF2 Iteration Count

**Severity:** MEDIUM  
**Location:** `Security/SymmetricEncryption/AeadCryptographyProvider.cs` (line 38), `Security/KeyDerivation/Pkcs5S2KeyGenerator.cs` (line 14)

The default key derivation iteration count is only 1,000:

```csharp
public virtual int KeyDerivationIterations { get; set; } = 1000;
```

OWASP currently recommends at least 600,000 iterations for PBKDF2-SHA256 (2023 guidance). The minimum of 1,000 in the `Pkcs5S2KeyGenerator` constructor allows dangerously weak configurations.

**Recommendation:** Increase the default to at least 100,000 (ideally 600,000). Raise the minimum enforced in `Pkcs5S2KeyGenerator` accordingly. Add a migration path for existing encrypted files.

### 1.4 EncryptedSecureString Disposes Static Machine Key

**Severity:** MEDIUM  
**Location:** `Security/EncryptedSecureString.cs` (lines 62-66)

The `Dispose` method disposes the static `_machineKey`, which would break all other instances:

```csharp
private void Dispose(bool disposing)
{
    if (!disposing) return;
    _machineKey?.Dispose();  // Static field!
    _secureString?.Dispose();
}
```

**Recommendation:** Only dispose the instance field `_secureString`. The static `_machineKey` should be managed through application lifecycle, not individual instance disposal.

### 1.5 Temporary Private Key Files Left on Disk

**Severity:** MEDIUM  
**Location:** `Connection/Protocol/PuttyBase.cs` (lines 125-131, 345-351)

Private keys from credential vaults are written to temporary files. Although cleanup is attempted in `finally`, the 500ms sleep before deletion is fragile and the file may not be securely erased:

```csharp
finally
{
    if (!string.IsNullOrEmpty(optionalTemporaryPrivateKeyPath))
    {
        System.Threading.Thread.Sleep(500);
        System.IO.File.Delete(optionalTemporaryPrivateKeyPath);
    }
}
```

**Recommendation:** Overwrite the file contents with zeros before deletion. Use `FileOptions.DeleteOnClose` where possible. Consider using named pipes or in-memory transfer instead of temp files.

### 1.6 PowerShell Password Passed as Command-Line Argument

**Severity:** HIGH  
**Location:** `Connection/Protocol/PowerShell/Connection.Protocol.PowerShell.cs` (line 191)

The password is embedded directly in the PowerShell command-line arguments:

```csharp
string arguments = $@"-NoExit -Command ""& {{ {psScriptBlock} }}"" -Hostname ""'{_connectionInfo.Hostname}'"" -Username ""'{psUsername}'"" -Password ""'{_connectionInfo.Password}'"" -LoginAttempts {psLoginAttempts}";
```

Command-line arguments are visible via `tasklist`, Process Explorer, and system logs. This is a direct credential exposure.

**Recommendation:** Use the named pipe approach (already used for PuTTY) or pass credentials via environment variables or stdin.

### 1.7 MySQL Connection String Built via String Interpolation

**Severity:** MEDIUM  
**Location:** `Config/DatabaseConnectors/MySqlDatabaseConnector.cs` (line 52)

```csharp
_dbConnectionString = $"server={_dbHost};user={_dbUsername};database={_dbName};port={_dbPort};password={_dbPassword};";
```

If any parameter contains special characters (e.g., `;` or `=` in a password), it could corrupt or be exploited via the connection string. The MSSQL connector properly uses `SqlConnectionStringBuilder`, but the MySQL connector does not.

**Recommendation:** Use `MySqlConnectionStringBuilder` for safe construction.

### 1.8 `TrustServerCertificate = true` in MSSQL Connection

**Severity:** MEDIUM  
**Location:** `Config/DatabaseConnectors/MSSqlDatabaseConnector.cs` (line 71)

```csharp
TrustServerCertificate = true,
```

This disables certificate validation, making the connection vulnerable to MITM attacks. Combined with `ApplicationIntent = ReadOnly` (line 63), which may also be incorrect for a connection manager that writes data.

**Recommendation:** Make `TrustServerCertificate` configurable (default `false`). Fix `ApplicationIntent` to `ReadWrite` for the save path.

---

## 2. Architecture & Design Improvements

### 2.1 Massive Code Duplication in External Credential Provider Logic

**Location:** `Connection/Protocol/RDP/RdpProtocol.cs` (SetCredentials, SetRdGateway), `Connection/Protocol/PuttyBase.cs` (Connect)

The same external credential provider `if/else if` chain is duplicated at least **4 times** across `SetCredentials()`, `SetRdGateway()`, and `PuttyBase.Connect()`. Each copy handles DelineaSecretServer, ClickstudiosPasswordState, OnePassword, and VaultOpenbao identically.

**Recommendation:** Extract a unified `ICredentialResolver` service:

```csharp
public interface ICredentialResolver
{
    ResolvedCredentials Resolve(ConnectionInfo info);
}
```

This would centralize credential fetching, reduce 200+ lines of duplicated code, and make adding new credential providers a single-point change.

### 2.2 God Class: `AbstractConnectionRecord`

**Location:** `Connection/AbstractConnectionRecord.cs` (1,135 lines)

This class contains 80+ fields covering RDP settings, VNC settings, gateway config, redirect config, appearance, and more. This violates the Single Responsibility Principle and makes the class very difficult to maintain.

**Recommendation:** Decompose into protocol-specific configuration objects:

- `RdpConnectionSettings`
- `VncConnectionSettings`
- `GatewaySettings`
- `RedirectSettings`
- `AppearanceSettings`

### 2.3 Static Singletons and Global State

**Location:** `App/Runtime.cs`

The `Runtime` class exposes numerous static properties that serve as a global service locator:

```csharp
public static MessageCollector MessageCollector { get; }
public static SecureString EncryptionKey { get; set; }
public static ConnectionsService ConnectionsService { get; }
```

This makes unit testing extremely difficult and creates tight coupling throughout the codebase.

**Recommendation:** Introduce dependency injection (even a simple DI container). Start by injecting `MessageCollector` and `ConnectionsService` as constructor parameters where possible.

### 2.4 Reflection-Heavy Property Inheritance

**Location:** `Connection/ConnectionInfo.cs` (lines 193-247)

Property inheritance uses reflection on every property access:

```csharp
private bool TryGetInheritedPropertyValue<TPropertyType>(string propertyName, out TPropertyType inheritedValue)
{
    Type connectionInfoType = Parent.GetType();
    PropertyInfo parentPropertyInfo = connectionInfoType.GetProperty(propertyName);
    inheritedValue = (TPropertyType)parentPropertyInfo.GetValue(Parent, null);
}
```

This is called on every property getter, which is expensive.

**Recommendation:** Cache `PropertyInfo` lookups in a static dictionary. Consider generating the inheritance resolution at compile-time or using source generators.

---

## 3. Code Quality & Maintainability

### 3.1 Inconsistent Naming Conventions

Examples:
- `isRunning()` (PuttyBase.cs line 62) - should be `IsRunning()` per C# conventions
- `getSSHConnectionInfoByName()` (ConnectionInitiator.cs line 258) - should be `GetSshConnectionInfoByName()`
- `_isPuttyNg` vs `_connectionInfo` - inconsistent prefix usage
- `DBDate()`, `DBTimeStampNow()` (MiscTools.cs) - should use full words
- `LDAP://` string comparisons use `StringComparison.OrdinalIgnoreCase` in some places and `==` in others

**Recommendation:** Enforce consistent C# naming conventions via `.editorconfig` and analyzers.

### 3.2 Dead Code and Commented-Out Code

Multiple locations contain commented-out code that should be cleaned up:
- `AbstractConnectionRecord.cs` line 37: `//private SecureString _password = null;`
- `RdpProtocol.cs` lines 429, 567: commented-out password lines
- `PuttyBase.cs` line 111: `//string password = InterfaceControl.Info?.Password?.ConvertToUnsecureString() ?? "";`
- `AbstractConnectionRecord.cs` line 984: TODO comment about VNC properties being "never hooked up"

**Recommendation:** Remove all commented-out code. Use version control history instead. Address or remove TODO comments.

### 3.3 Missing XML Documentation

Nearly all public APIs lack XML documentation comments. For a library/application of this size (~760 source files), this makes onboarding and maintenance significantly harder.

**Recommendation:** Add XML documentation to all public classes, interfaces, and methods. Enable `CS1591` warning for public API documentation enforcement.

### 3.4 Magic Strings and Numbers

Examples:
- `"windows"`, `"custom"` for credential settings (RdpProtocol.cs lines 618-666)
- `0x50` for PuTTY settings menu ID (PuttyBase.cs line 30)
- `60000` for timeout (ConnectionInitiator.cs line 178)
- `5000` for reconnect timer (ProtocolBase.cs line 65)
- `0xB08` for normal disconnect (RdpProtocol.cs line 909)

**Recommendation:** Extract these to named constants or enums. The credential mode strings should be an enum.

---

## 4. Error Handling & Reliability

### 4.1 Empty Catch Blocks

**Location:** Multiple files

Several empty catch blocks silently swallow exceptions:

- `ProgramRoot.cs` (2 instances)
- `DPI_Per_Monitor.cs` (6 instances)
- `PowerShell/Connection.Protocol.PowerShell.cs` (3 instances)
- `ConnectionInitiator.cs` line 75: EC2 instance data fetch failure silently ignored

**Recommendation:** At minimum, log the exception. Replace empty catches with specific exception handling or remove them if truly appropriate.

### 4.2 ProtocolBase.Dispose() Is Inverted

**Location:** `Connection/Protocol/ProtocolBase.cs` (lines 346-350)

```csharp
private void Dispose(bool disposing)
{
    if (disposing) return;  // BUG: Should be if (!disposing) return;
    tmrReconnect?.Dispose();
}
```

The dispose guard is inverted - it returns when `disposing` is `true`, meaning the timer is **never** disposed during normal `Dispose()` calls (only during finalization, which never happens since there's no finalizer).

**Recommendation:** Fix the condition to `if (!disposing) return;` to properly dispose managed resources.

### 4.3 Thread.Sleep + Application.DoEvents in ActiveX Initialization

**Location:** `Connection/Protocol/RDP/RdpProtocol.cs` (lines 175-179)

```csharp
while (!Control.Created)
{
    Thread.Sleep(50);
    Application.DoEvents();
}
```

`Application.DoEvents()` can cause re-entrancy bugs and unpredictable behavior. This spin-wait loop can also hang indefinitely.

**Recommendation:** Use an async pattern or event-based waiting. At minimum, add a timeout to prevent infinite loops.

### 4.4 Missing Null Checks Before Dereferencing

**Location:** `Connection/Protocol/RDP/RdpProtocol.cs` (line 955)

```csharp
((ConnectionTab)Control.Parent.Parent).Focus();
```

No null checks on `Control.Parent` or `Control.Parent.Parent`. This will throw `NullReferenceException` if the control hierarchy is unexpected.

### 4.5 Race Condition in PuttyHandle Wait Loop

**Location:** `Connection/Protocol/PuttyBase.cs` (lines 297-298)

```csharp
while (PuttyHandle.ToInt32() == 0 &
       Environment.TickCount < startTicks + Properties.OptionsAdvancedPage.Default.MaxPuttyWaitTime * 1000)
```

Uses bitwise AND (`&`) instead of logical AND (`&&`), preventing short-circuit evaluation. Also, `Environment.TickCount` wraps around every ~24.8 days, which could cause issues.

**Recommendation:** Use `&&` and `Stopwatch` instead of `Environment.TickCount`.

---

## 5. Performance Improvements

### 5.1 Reflection on Every Property Access

**Location:** `Connection/AbstractConnectionRecord.cs` (line 1116-1118)

```csharp
protected virtual TPropertyType GetPropertyValue<TPropertyType>(string propertyName, TPropertyType value)
{
    return (TPropertyType)GetType().GetProperty(propertyName)?.GetValue(this, null);
}
```

This performs reflection on **every single property getter call** for the base class. In `ConnectionInfo`, it adds another reflection layer for inheritance checking. With potentially thousands of connections, this adds up.

**Recommendation:** Cache `PropertyInfo` objects in a static `ConcurrentDictionary<string, PropertyInfo>`. Better yet, refactor to avoid reflection entirely by using explicit delegation.

### 5.2 RandomGenerator Creates New SecureRandom Per Call

**Location:** `Security/RandomGenerator.cs` (line 14)

```csharp
public static string RandomString(int length)
{
    SecureRandom randomGen = new();
```

Creating a new `SecureRandom` instance for each call is expensive due to seeding.

**Recommendation:** Use a static `SecureRandom` instance (thread-safe) or a `ThreadLocal<SecureRandom>`.

### 5.3 String Concatenation in Loops

**Location:** `Security/EncryptedSecureString.cs` (lines 51-54)

```csharp
string machineKeyString = "";
for (int x = 0; x < keySize; x++)
{
    machineKeyString += (char)random.Next(33, 126);
}
```

**Recommendation:** Use `StringBuilder` or `char[]` array.

---

## 6. Testing Gaps

### 6.1 Low Test-to-Source Ratio

The project has 147 test files for 760 source files (~19% ratio). Key areas lacking test coverage:

- **Protocol implementations:** Only `IntegratedProgramTests`, `ProtocolAnydeskTests`, `ProtocolListTests`, and `RdpProtocol8ResizeTests` exist. No tests for SSH, VNC, Telnet, PowerShell, or WSL protocols.
- **Database connectors:** No tests for `MSSqlDatabaseConnector` or `MySqlDatabaseConnector`.
- **Configuration loaders/savers:** Only `XmlConnectionsLoaderTests` exists. No tests for `SqlConnectionsLoader`, `SqlConnectionsSaver`, or `XmlConnectionsSaver`.
- **Connection initiation logic:** `ConnectionInitiatorTests` exists but the SSH tunnel logic is complex and would benefit from more focused testing.
- **External credential providers:** Zero tests for any external credential provider integration.

**Recommendation:** Prioritize integration tests for the credential resolution, SQL connectivity, and protocol initialization paths. Add unit tests for all serializers and database connectors.

### 6.2 Test Projects Not in Solution File

The `mRemoteNGTests` and `mRemoteNGSpecs` projects are not included in `mRemoteNG.sln`. This means they won't build as part of the normal solution build process.

**Recommendation:** Add test projects to the solution file and integrate them into CI/CD.

---

## 7. Dependency & Build Improvements

### 7.1 Package Versions Not Pinned

**Location:** `mRemoteNG/mRemoteNG.csproj` (lines 124-149)

All `<PackageReference>` elements lack version attributes:

```xml
<PackageReference Include="BouncyCastle.Cryptography" />
<PackageReference Include="SSH.NET" />
<PackageReference Include="Newtonsoft.Json" />
```

This relies on a lock file or Central Package Management to be deterministic. If neither is configured, builds may pull different versions.

**Recommendation:** Either pin explicit versions in the `.csproj` or ensure Central Package Management (`Directory.Packages.props`) is properly configured and committed.

### 7.2 OpenCover and ReportGenerator as Package References

**Location:** `mRemoteNG/mRemoteNG.csproj` (lines 143-144)

```xml
<PackageReference Include="OpenCover" />
<PackageReference Include="ReportGenerator" />
```

These are development/CI tools, not runtime dependencies. They should not be in the main project.

**Recommendation:** Move these to the test project or use them as dotnet tools (`dotnet tool install`).

### 7.3 Targeting .NET 10 Preview

**Location:** `mRemoteNG/mRemoteNG.csproj` (line 10)

```xml
<TargetFramework>net10.0-windows10.0.26100.0</TargetFramework>
```

.NET 10 is in preview. Using a preview framework for production code can lead to breaking changes.

**Recommendation:** Target the latest LTS release (.NET 8) or the latest stable release (.NET 9) with a plan to migrate to .NET 10 when it reaches GA.

---

## 8. Protocol-Specific Issues

### 8.1 Hardcoded PowerShell Path

**Location:** `Connection/Protocol/PowerShell/Connection.Protocol.PowerShell.cs` (line 44)

```csharp
string psExe = @"C:\Program Files\PowerShell\7\pwsh.exe";
```

This hardcodes the PowerShell 7 path and ignores PowerShell installed in other locations or via Windows Store.

**Recommendation:** Search the PATH for `pwsh.exe` first, fall back to known locations, and make the path configurable in settings.

### 8.2 RDP COM Object Recreation on Exception

**Location:** `Connection/Protocol/RDP/RdpProtocol.cs` (lines 57-79)

When an `InvalidComObjectException` occurs, the SmartSize getter/setter creates a brand-new COM object:

```csharp
catch (System.Runtime.InteropServices.InvalidComObjectException)
{
    _rdpClient = new MsRdpClient6NotSafeForScripting();
    return _rdpClient.AdvancedSettings2.SmartSizing;
}
```

This creates an orphaned, unconfigured COM object that replaces the properly initialized one.

**Recommendation:** Instead of silently creating new instances, log the error and handle the disconnected state properly. Consider reconnection instead of object replacement.

### 8.3 ProtocolFactory Returns null Instead of Throwing

**Location:** `Connection/Protocol/ProtocolFactory.cs` (line 67)

```csharp
return default(ProtocolBase); // returns null
```

If an unrecognized protocol type is used, the factory silently returns `null`, leading to `NullReferenceException` downstream.

**Recommendation:** Throw an `ArgumentOutOfRangeException` for unsupported protocol types.

---

## 9. Configuration & Serialization

### 9.1 SQL Connections Still Use Legacy Crypto

**Location:** `Config/Connections/SqlConnectionsLoader.cs` (line 38), `Config/Connections/SqlConnectionsSaver.cs` (line 157)

Both the SQL loader and saver explicitly use `LegacyRijndaelCryptographyProvider`:

```csharp
LegacyRijndaelCryptographyProvider cryptoProvider = new();
```

This means all SQL-stored connections use the weak MD5-based encryption.

**Recommendation:** Migrate SQL connections to use `AeadCryptographyProvider`. Add a database migration step to re-encrypt existing data.

### 9.2 `PrepareValueForDB` Is Insufficient

**Location:** `Tools/MiscTools.cs` (lines 118-121)

```csharp
public static string PrepareValueForDB(string Text)
{
    return Text.Replace("\'", "\'\'");
}
```

This only escapes single quotes, which is insufficient for SQL injection prevention. If this is used anywhere to build SQL queries dynamically, it's a security risk.

**Recommendation:** Audit all usages of this method. Use parameterized queries exclusively (which are already used in some places like `SqlConnectionsSaver.UpdateRootNodeTable()`). Remove this method if it's no longer needed.

### 9.3 Missing Database Connector IDisposable Pattern

**Location:** `Config/DatabaseConnectors/MSSqlDatabaseConnector.cs`, `MySqlDatabaseConnector.cs`

Both database connectors implement `IDisposable` but don't implement the full pattern (no `disposed` guard, no `GC.SuppressFinalize`). The `Dispose(bool)` method can throw if the connection is already disposed.

**Recommendation:** Add a `_disposed` flag and check it before disposing. Implement the standard dispose pattern.

### 9.4 No Connection String Encryption for SQL Credentials

The SQL server password is stored in application settings and loaded directly. If an attacker gains access to the settings file, they get the database credentials.

**Recommendation:** Encrypt SQL credentials in settings using DPAPI or the `AeadCryptographyProvider`.

---

## 10. UI/UX Improvements

### 10.1 Synchronous File Operations on UI Thread

**Location:** `App/Runtime.cs` (LoadConnections)

Connection loading is done on the UI thread when `withDialog=false`. The async version (`LoadConnectionsAsync`) creates a raw `Thread` instead of using `Task.Run()`.

**Recommendation:** Use `async/await` with `Task.Run()` for all file/database operations. Show a progress indicator during loading.

### 10.2 MessageBox on Non-UI Thread

**Location:** `Connection/Protocol/RDP/RdpProtocol.cs` (line 898)

```csharp
MessageBox.Show($@"The {connectionInfo.Name} session was disconnected...");
```

This is called from the RDP event handler which may not be on the UI thread.

**Recommendation:** Marshal to the UI thread before showing MessageBox dialogs.

### 10.3 SendKeys for Opening Commands

**Location:** `Connection/Protocol/PuttyBase.cs` (lines 328-331)

```csharp
NativeMethods.SetForegroundWindow(PuttyHandle);
string finalCommand = InterfaceControl.Info.OpeningCommand.TrimEnd() + "\n";
SendKeys.SendWait(finalCommand);
```

`SendKeys.SendWait()` is unreliable and can send keystrokes to the wrong window in race conditions.

**Recommendation:** Use named pipes, stdin redirection, or PuTTY's `-m` command file option for reliable command injection.

---

## Summary of Priority Actions

| Priority | Issue | Impact | Status |
|----------|-------|--------|--------|
| P0 | Passwords stored as plain strings (#1.1) | Credential exposure in memory | Noted (requires major refactor) |
| P0 | PowerShell password in CLI args (#1.6) | Credential exposure via process list | **FIXED** - Uses env vars now |
| P0 | ProtocolBase.Dispose inverted (#4.2) | Resource leak in every connection | **FIXED** |
| P1 | MD5 key derivation in legacy crypto (#1.2) | Weak encryption for SQL connections | Noted (requires migration path) |
| P1 | Low PBKDF2 iterations (#1.3) | Weak key derivation | **FIXED** - Increased to 100,000 |
| P1 | Duplicated credential provider code (#2.1) | Maintainability & bug risk | **FIXED** - CredentialResolver created |
| P1 | MySQL connection string injection (#1.7) | SQL injection via connection string | **FIXED** - Uses builder now |
| P2 | Reflection on every property access (#5.1) | Performance with many connections | Noted |
| P2 | Test coverage gaps (#6.1) | Regression risk | Noted |
| P2 | Empty catch blocks (#4.1) | Silent failures | Noted |
| P3 | Naming convention inconsistencies (#3.1) | Code readability | Noted |
| P3 | Hardcoded paths (#8.1) | Portability | Noted |
| P3 | Unpinned package versions (#7.1) | Build reproducibility | Noted |

## Additional Fixes Deployed

| Fix | Description |
|-----|-------------|
| EncryptedSecureString.Dispose | No longer disposes static _machineKey shared by all instances |
| ProtocolFactory null return | Now throws ArgumentOutOfRangeException for unsupported protocols |
| RandomGenerator | Uses shared static SecureRandom instance instead of creating new per call |
| PuttyBase bitwise AND | Changed `&` to `&&` for proper short-circuit evaluation |
| EncryptedSecureString key gen | Uses char[] array instead of string concatenation in loop |

## New Features Added

| Feature | Description |
|---------|-------------|
| RDP Span All Screens | Multi-monitor spanning via UseMultimon + bounding rectangle calculation |
| AI Security Scanner | LLM-powered system security analysis (OpenAI, Claude, Gemini, Grok) |
| CredentialResolver | Centralized external credential provider resolution service |
