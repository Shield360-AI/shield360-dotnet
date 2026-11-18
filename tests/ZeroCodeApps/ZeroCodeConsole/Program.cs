using System.Reflection;

// No reference to Shield360: everything is looked up by name, so it is found only when the startup hook loaded it.
static Type? Find(string name) => Type.GetType(name + ", Shield360", throwOnError: false);

var loaded = AppDomain.CurrentDomain.GetAssemblies().Any(a => a.GetName().Name == "Shield360");
var sdk = loaded ? Find("Shield360.Shield360Sdk") : null;
var initialized = sdk?.GetProperty("IsInitialized")?.GetValue(null) as bool? ?? false;
var rasp = (loaded ? Find("Shield360.Rasp.Shield360Rasp") : null)?.GetProperty("IsActive")?.GetValue(null) as bool? ?? false;

var second = "none";
if (args.Contains("--init-again") && sdk is not null)
{
    var init = sdk.GetMethod("Init", new[] { Find("Shield360.Shield360Options")! })!;
    try
    {
        init.Invoke(null, new object?[] { null });
        second = "ok";
    }
    catch (TargetInvocationException e)
    {
        second = e.InnerException?.GetType().Name ?? "error";
    }
}

Console.WriteLine($"RESULT loaded={loaded} initialized={initialized} rasp={rasp} second={second}");
Console.WriteLine($"RUNTIME {Environment.Version.Major}");
