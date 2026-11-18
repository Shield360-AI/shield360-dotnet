using System;

namespace Shield360;

/// <summary>An error raised by the Shield360 SDK. Messages never contain API keys or headers.</summary>
public class Shield360Exception : Exception
{
    /// <summary>Creates the exception.</summary>
    public Shield360Exception()
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public Shield360Exception(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and the error that caused it.</summary>
    public Shield360Exception(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The HTTP status code the server returned, when the error came from a response.</summary>
    public int? StatusCode { get; init; }
}
