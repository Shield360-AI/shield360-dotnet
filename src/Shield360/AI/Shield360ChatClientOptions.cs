namespace Shield360.AI;

/// <summary>
/// Per-client settings for <see cref="Shield360ChatClient"/>. Anything left
/// unset comes from the active <see cref="Shield360Sdk.Init(Shield360Options?)"/>
/// or <c>AddShield360</c> configuration, then from the defaults.
/// </summary>
public sealed class Shield360ChatClientOptions
{
    /// <summary>The application name recorded as <c>service.name</c>.</summary>
    public string? ApplicationName { get; set; }

    /// <summary>The environment recorded as <c>deployment.environment</c>.</summary>
    public string? Environment { get; set; }

    /// <summary>Record prompt and response text. Off unless set here or in the SDK configuration.</summary>
    public bool? CaptureMessageContent { get; set; }

    /// <summary>The prices used for <c>gen_ai.usage.cost</c>.</summary>
    public Pricing? Pricing { get; set; }

    /// <summary>
    /// The provider name (<c>gen_ai.provider.name</c>) to use when the inner
    /// client does not report one through <c>ChatClientMetadata</c>.
    /// </summary>
    public string? ProviderName { get; set; }
}
