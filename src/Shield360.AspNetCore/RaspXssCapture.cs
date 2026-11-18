using System;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Shield360.Rasp;

namespace Shield360.AspNetCore;

/// <summary>
/// Passes every write of the response body straight through and keeps a copy of an
/// HTML body (at most 1 MiB, uncompressed) for the reflected-XSS check. It never
/// changes, delays or fails a write: a body it cannot keep is simply not checked.
/// Whether to keep a copy is decided once, at the first write or flush, from the
/// response's content type and encoding.
/// </summary>
internal sealed class RaspXssCapture : Stream
{
    private readonly Stream _inner;
    private readonly HttpResponse _response;
    private MemoryStream? _copy = new();
    private bool _decided;

    public RaspXssCapture(Stream inner, HttpResponse response)
    {
        _inner = inner;
        _response = response;
    }

    /// <summary>The captured HTML body, or null when there is none to check.</summary>
    public string? Text()
    {
        var copy = _copy;
        if (copy is null || !_decided || copy.Length == 0)
        {
            return null;
        }

        try
        {
            return Encoding.UTF8.GetString(copy.GetBuffer(), 0, (int)copy.Length);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    public string? ContentType => _response.ContentType;

    /// <summary>Decides (once) whether this response is kept: HTML, not compressed. Returns the decision.</summary>
    public bool Decide()
    {
        if (_decided)
        {
            return _copy is not null;
        }

        _decided = true;
        try
        {
            var type = _response.ContentType ?? string.Empty;
            var encoding = _response.Headers.ContentEncoding.ToString();
            if (type.IndexOf("html", StringComparison.OrdinalIgnoreCase) < 0 ||
                (encoding.Length > 0 && !string.Equals(encoding, "identity", StringComparison.OrdinalIgnoreCase)))
            {
                _copy = null;
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            _copy = null;
        }

        return _copy is not null;
    }

    private void Keep(ReadOnlySpan<byte> data)
    {
        if (!Decide())
        {
            return;
        }

        var copy = _copy!;
        try
        {
            if (copy.Length + data.Length > RaspDetect.MaxXssBody)
            {
                _copy = null;
                return;
            }

            copy.Write(data);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            _copy = null;
        }
    }

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        Keep(buffer.AsSpan(offset, count));
        _inner.Write(buffer, offset, count);
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        Keep(buffer);
        _inner.Write(buffer);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        Keep(buffer.AsSpan(offset, count));
        return _inner.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Keep(buffer.Span);
        return _inner.WriteAsync(buffer, cancellationToken);
    }
}

/// <summary>
/// The response's <see cref="PipeWriter"/> while the XSS check listens. At the first use
/// it picks its target once: for a response that is kept (HTML), a writer over
/// <see cref="RaspXssCapture"/>; for any other response, the server's own writer, so a
/// JSON or event-stream response runs exactly as without RASP. A flush always reaches
/// the server, even with nothing buffered, so headers go out when the app asks.
/// </summary>
internal sealed class RaspXssPipeWriter : PipeWriter
{
    private readonly IHttpResponseBodyFeature _prior;
    private readonly RaspXssCapture _capture;
    private PipeWriter? _target;
    private bool _captured;

    public RaspXssPipeWriter(IHttpResponseBodyFeature prior, RaspXssCapture capture)
    {
        _prior = prior;
        _capture = capture;
    }

    private PipeWriter Target
    {
        get
        {
            if (_target is null)
            {
                _captured = _capture.Decide();
                _target = _captured ? Create(_capture, new StreamPipeWriterOptions(leaveOpen: true)) : _prior.Writer;
            }

            return _target;
        }
    }

    /// <summary>Whether the writer was used and writes through the capture (so it holds bytes to flush at the end).</summary>
    public bool Captures => _target is not null && _captured;

    public override bool CanGetUnflushedBytes => Target.CanGetUnflushedBytes;

    public override long UnflushedBytes => Target.UnflushedBytes;

    public override void Advance(int bytes) => Target.Advance(bytes);

    public override Memory<byte> GetMemory(int sizeHint = 0) => Target.GetMemory(sizeHint);

    public override Span<byte> GetSpan(int sizeHint = 0) => Target.GetSpan(sizeHint);

    public override void CancelPendingFlush() => _target?.CancelPendingFlush();

    public override void Complete(Exception? exception = null) => Target.Complete(exception);

    public override ValueTask CompleteAsync(Exception? exception = null) => Target.CompleteAsync(exception);

    public override async ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
    {
        var target = Target;
        var result = await target.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (_captured)
        {
            // A stream writer with nothing buffered does not flush its stream: flush it here.
            await _capture.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        return result;
    }
}

/// <summary>
/// The response body feature while the XSS check listens: writes through
/// <see cref="Stream"/> or <see cref="Writer"/> reach <see cref="RaspXssCapture"/> (HTML)
/// or the server directly (anything else); start, completion, buffering and send-file
/// go to the server's feature unchanged (a file sent with <c>SendFileAsync</c> is not checked).
/// </summary>
internal sealed class RaspXssBodyFeature : IHttpResponseBodyFeature
{
    private readonly IHttpResponseBodyFeature _prior;
    private RaspXssPipeWriter? _writer;

    public RaspXssBodyFeature(IHttpResponseBodyFeature prior, RaspXssCapture capture)
    {
        _prior = prior;
        Capture = capture;
    }

    public RaspXssCapture Capture { get; }

    public Stream Stream => Capture;

    public PipeWriter Writer => _writer ??= new RaspXssPipeWriter(_prior, Capture);

    public void DisableBuffering() => _prior.DisableBuffering();

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await FlushWriterAsync(cancellationToken).ConfigureAwait(false);
        await _prior.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellationToken = default)
    {
        await FlushWriterAsync(cancellationToken).ConfigureAwait(false);
        await _prior.SendFileAsync(path, offset, count, cancellationToken).ConfigureAwait(false);
    }

    public async Task CompleteAsync()
    {
        await FlushWriterAsync().ConfigureAwait(false);
        await _prior.CompleteAsync().ConfigureAwait(false);
    }

    /// <summary>Writes what the app left in a capturing <see cref="Writer"/> through to the server (nothing otherwise).</summary>
    public async Task FlushWriterAsync(CancellationToken cancellationToken = default)
    {
        if (_writer is { Captures: true })
        {
            await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
