using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace OpenClaw.Shared.RustSidecar;

internal sealed class WindowsSidecarProcessLauncher
{
    private static readonly byte[] BootstrapMagic = "OCSB"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private const ushort BootstrapVersion = 1;
    private const int BootstrapFixedBytes = 52;
    private const int MaximumBootstrapPayloadBytes = 1024;
    private const uint MaximumBootstrapFrameBytes = 4096;
    private const long MaximumArtifactBytes = 256L * 1024 * 1024;
    private static readonly TimeSpan BootstrapWriteTimeout = TimeSpan.FromSeconds(5);
    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileAttributeReparsePoint = 0x00000400;

    internal async Task<WindowsSidecarProcess> LaunchAsync(
        string artifactPath,
        string expectedSha256,
        string sessionId,
        ulong generation,
        ReadOnlyMemory<byte> sessionKey,
        uint bootstrapFrameLimit,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(artifactPath);
        var expectedHash = ParseSha256(expectedSha256);
        ValidateBootstrap(sessionId, generation, sessionKey, bootstrapFrameLimit);
        using var pathLocks = LockArtifactPath(fullPath);
        await using var artifact = OpenArtifact(fullPath);
        if (artifact.Length is <= 0 or > MaximumArtifactBytes)
            throw new SidecarProtocolException("Rust sidecar artifact size is invalid.");
        var actualHash = await SHA256.HashDataAsync(artifact, cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
            throw new SidecarProtocolException("Rust sidecar artifact hash does not match its exact pin.");

        var startInfo = new ProcessStartInfo(fullPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = false
        };
        RemoveLegacyBootstrapEnvironment(startInfo);
        var process = Process.Start(startInfo) ?? throw new SidecarProtocolException(
            "Failed to start the verified Rust sidecar artifact.");
        var launched = new WindowsSidecarProcess(
            process,
            $"sha256:{Convert.ToHexString(actualHash).ToLowerInvariant()}");
        try
        {
            await WriteBootstrapAsync(
                launched.StandardInput,
                sessionId,
                generation,
                sessionKey,
                bootstrapFrameLimit,
                cancellationToken).ConfigureAwait(false);
            return launched;
        }
        catch
        {
            launched.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualHash);
            CryptographicOperations.ZeroMemory(expectedHash);
        }
    }

    private static async Task WriteBootstrapAsync(
        Stream stream,
        string sessionId,
        ulong generation,
        ReadOnlyMemory<byte> sessionKey,
        uint bootstrapFrameLimit,
        CancellationToken cancellationToken)
    {
        var sessionBytes = StrictUtf8.GetBytes(sessionId);
        var payload = new byte[checked(BootstrapFixedBytes + sessionBytes.Length)];
        try
        {
            BootstrapMagic.CopyTo(payload, 0);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(4, 2), BootstrapVersion);
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(6, 8), generation);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(14, 4), bootstrapFrameLimit);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(18, 2), checked((ushort)sessionBytes.Length));
            sessionKey.Span.CopyTo(payload.AsSpan(20, 32));
            sessionBytes.CopyTo(payload, BootstrapFixedBytes);
            var prefix = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(prefix, checked((uint)payload.Length));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(BootstrapWriteTimeout);
            await stream.WriteAsync(prefix, timeout.Token).ConfigureAwait(false);
            await stream.WriteAsync(payload, timeout.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeout.Token).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(sessionBytes);
        }
    }

    private static void ValidateBootstrap(
        string sessionId,
        ulong generation,
        ReadOnlyMemory<byte> sessionKey,
        uint bootstrapFrameLimit)
    {
        var sessionBytes = StrictUtf8.GetByteCount(sessionId);
        if (sessionBytes == 0 || sessionBytes > MaximumBootstrapPayloadBytes - BootstrapFixedBytes)
            throw new ArgumentOutOfRangeException(nameof(sessionId));
        if (generation == 0)
            throw new ArgumentOutOfRangeException(nameof(generation));
        if (sessionKey.Length != 32)
            throw new ArgumentException("Sidecar session key must contain exactly 32 bytes.", nameof(sessionKey));
        if (bootstrapFrameLimit is < 65 or > MaximumBootstrapFrameBytes)
            throw new ArgumentOutOfRangeException(nameof(bootstrapFrameLimit));
    }

    private static byte[] ParseSha256(string expectedSha256)
    {
        if (expectedSha256.Length != 64)
            throw new ArgumentException("Expected artifact SHA-256 must contain 64 hexadecimal characters.", nameof(expectedSha256));
        try
        {
            return Convert.FromHexString(expectedSha256);
        }
        catch (FormatException error)
        {
            throw new ArgumentException("Expected artifact SHA-256 is not hexadecimal.", nameof(expectedSha256), error);
        }
    }

    private static void RemoveLegacyBootstrapEnvironment(ProcessStartInfo startInfo)
    {
        startInfo.Environment.Remove("OPENCLAW_SIDECAR_SESSION_ID");
        startInfo.Environment.Remove("OPENCLAW_SIDECAR_GENERATION");
        startInfo.Environment.Remove("OPENCLAW_SIDECAR_KEY_BASE64");
    }

    private static PathLockCollection LockArtifactPath(string fullPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The Windows sidecar launcher requires Windows.");

        var parents = new Stack<string>();
        for (var parent = Directory.GetParent(fullPath); parent?.Parent is not null; parent = parent.Parent)
            parents.Push(parent.FullName);

        var locks = new PathLockCollection();
        try
        {
            foreach (var parent in parents)
            {
                var handle = OpenPathHandle(
                    parent,
                    FileReadAttributes,
                    FileFlagBackupSemantics | FileFlagOpenReparsePoint);
                RejectReparsePoint(handle, parent);
                locks.Add(handle);
            }
            return locks;
        }
        catch
        {
            locks.Dispose();
            throw;
        }
    }

    private static FileStream OpenArtifact(string fullPath)
    {
        var handle = OpenPathHandle(
            fullPath,
            GenericRead,
            FileFlagOpenReparsePoint | FileFlagSequentialScan | FileFlagOverlapped);
        try
        {
            RejectReparsePoint(handle, fullPath);
            return new FileStream(handle, FileAccess.Read, bufferSize: 64 * 1024, isAsync: true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenPathHandle(string path, uint access, uint flags)
    {
        var handle = CreateFileW(path, access, FileShareRead, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new SidecarProtocolException(
                $"Could not lock Rust sidecar artifact path '{path}': {new Win32Exception(error).Message}");
        }
        return handle;
    }

    private static void RejectReparsePoint(SafeFileHandle handle, string path)
    {
        if (!GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileAttributeTagInfo,
                out var info,
                (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
        {
            var error = Marshal.GetLastWin32Error();
            throw new SidecarProtocolException(
                $"Could not inspect Rust sidecar artifact path '{path}': {new Win32Exception(error).Message}");
        }
        if ((info.FileAttributes & FileAttributeReparsePoint) != 0)
            throw new SidecarProtocolException("Rust sidecar artifact path must not contain a reparse point.");
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        out FileAttributeTagInfo fileInformation,
        uint bufferSize);

    private enum FileInfoByHandleClass
    {
        FileAttributeTagInfo = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        internal uint FileAttributes;
        internal uint ReparseTag;
    }

    private sealed class PathLockCollection : IDisposable
    {
        private readonly List<SafeFileHandle> _handles = [];

        internal void Add(SafeFileHandle handle) => _handles.Add(handle);

        public void Dispose()
        {
            foreach (var handle in _handles)
                handle.Dispose();
            _handles.Clear();
        }
    }
}

internal sealed class WindowsSidecarProcess : IDisposable
{
    private readonly Process _process;
    private bool _disposed;

    internal WindowsSidecarProcess(Process process, string artifactIdentity)
    {
        _process = process;
        ArtifactIdentity = artifactIdentity;
    }

    internal string ArtifactIdentity { get; }
    internal Stream StandardInput => _process.StandardInput.BaseStream;
    internal Stream StandardOutput => _process.StandardOutput.BaseStream;
    internal ProcessStartInfo StartInfo => _process.StartInfo;
    internal bool HasExited => _process.HasExited;
    internal int ExitCode => _process.ExitCode;

    internal Task WaitForExitAsync(CancellationToken cancellationToken) =>
        _process.WaitForExitAsync(cancellationToken);

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        try
        {
            try { _process.StandardInput.Close(); }
            catch (IOException) { }
            catch (InvalidOperationException) { }

            if (_process.HasExited)
                return;
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(5000);
        }
        catch (InvalidOperationException)
        {
            // The process exited between the liveness check and cleanup.
        }
        finally
        {
            _process.Dispose();
        }
    }
}
