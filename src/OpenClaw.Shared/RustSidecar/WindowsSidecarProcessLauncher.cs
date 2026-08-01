using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

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
        if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
            throw new SidecarProtocolException("Rust sidecar artifact must not be a reparse point.");

        await using var artifact = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
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
