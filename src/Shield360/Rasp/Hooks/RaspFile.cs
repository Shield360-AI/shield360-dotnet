using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Shield360.Rasp;

/// <summary>The kinds of file access the RASP path check knows.</summary>
public enum RaspFileOperation
{
    /// <summary>Reading a file.</summary>
    Read,

    /// <summary>Creating or overwriting a file.</summary>
    Write,

    /// <summary>Appending to a file.</summary>
    Append,

    /// <summary>Deleting a file or directory.</summary>
    Delete,

    /// <summary>Moving or renaming (both paths are checked).</summary>
    Rename,

    /// <summary>Listing a directory.</summary>
    List,
}

/// <summary>
/// <see cref="File"/> methods with the RASP path check first (sdk/rasp/README.md, "Path"):
/// path traversal, absolute paths and NUL bytes from input, paths outside
/// <c>Allow.FileRoots</c>, well-known secret files, script writes during a request and
/// NTFS streams. In block mode a finding throws <see cref="Shield360RaspBlockedException"/>
/// before the file is touched. Use them where a path can hold request input.
/// </summary>
public static class RaspFile
{
    internal static FileOp Map(RaspFileOperation op) => op switch
    {
        RaspFileOperation.Write => FileOp.Write,
        RaspFileOperation.Append => FileOp.Append,
        RaspFileOperation.Delete => FileOp.Delete,
        RaspFileOperation.Rename => FileOp.Rename,
        RaspFileOperation.List => FileOp.List,
        _ => FileOp.Read,
    };

    /// <summary>The path check alone. Throws only the block exception.</summary>
    internal static void Check(string? path, FileOp op, string sink)
    {
        if (string.IsNullOrEmpty(path) || !RaspEngine.IsActive)
        {
            return;
        }

        RaspHooks.Run(
            sink,
            (ctx, inputs) => RaspDetect.FilePath(path, op, inputs, RaspEngine.AllowLists().FileRoots, ctx?.InRequest == true),
            requireInputs: false);
    }

    /// <summary>
    /// Both paths of a move or copy as one check: the finding with the strongest decision
    /// wins, so a finding in monitor or off mode never hides one that blocks, and only the
    /// winner is reported. Throws only the block exception.
    /// </summary>
    internal static void Check(string? first, FileOp firstOp, string? second, FileOp secondOp, string sink)
    {
        if (!RaspEngine.IsActive)
        {
            return;
        }

        RaspHooks.Run(
            sink,
            (ctx, inputs) =>
            {
                var roots = RaspEngine.AllowLists().FileRoots;
                var inRequest = ctx?.InRequest == true;
                return RaspEngine.Strongest(
                    string.IsNullOrEmpty(first) ? null : RaspDetect.FilePath(first!, firstOp, inputs, roots, inRequest),
                    string.IsNullOrEmpty(second) ? null : RaspDetect.FilePath(second!, secondOp, inputs, roots, inRequest));
            },
            requireInputs: false);
    }

    private static FileOp OpOf(FileMode mode, FileAccess access) =>
        access == FileAccess.Read && mode == FileMode.Open ? FileOp.Read
        : mode == FileMode.Append ? FileOp.Append
        : FileOp.Write;

    /// <summary><see cref="File.ReadAllText(string)"/>, checked.</summary>
    public static string ReadAllText(string path)
    {
        Check(path, FileOp.Read, "File.ReadAllText");
        return File.ReadAllText(path);
    }

    /// <summary><see cref="File.ReadAllText(string, Encoding)"/>, checked.</summary>
    public static string ReadAllText(string path, Encoding encoding)
    {
        Check(path, FileOp.Read, "File.ReadAllText");
        return File.ReadAllText(path, encoding);
    }

    /// <summary><see cref="File.ReadAllBytes(string)"/>, checked.</summary>
    public static byte[] ReadAllBytes(string path)
    {
        Check(path, FileOp.Read, "File.ReadAllBytes");
        return File.ReadAllBytes(path);
    }

    /// <summary><see cref="File.ReadAllLines(string)"/>, checked.</summary>
    public static string[] ReadAllLines(string path)
    {
        Check(path, FileOp.Read, "File.ReadAllLines");
        return File.ReadAllLines(path);
    }

    /// <summary><see cref="File.WriteAllText(string, string)"/>, checked.</summary>
    public static void WriteAllText(string path, string? contents)
    {
        Check(path, FileOp.Write, "File.WriteAllText");
        File.WriteAllText(path, contents);
    }

    /// <summary><see cref="File.WriteAllText(string, string, Encoding)"/>, checked.</summary>
    public static void WriteAllText(string path, string? contents, Encoding encoding)
    {
        Check(path, FileOp.Write, "File.WriteAllText");
        File.WriteAllText(path, contents, encoding);
    }

    /// <summary><see cref="File.WriteAllBytes(string, byte[])"/>, checked.</summary>
    public static void WriteAllBytes(string path, byte[] bytes)
    {
        Check(path, FileOp.Write, "File.WriteAllBytes");
        File.WriteAllBytes(path, bytes);
    }

    /// <summary><see cref="File.AppendAllText(string, string)"/>, checked.</summary>
    public static void AppendAllText(string path, string? contents)
    {
        Check(path, FileOp.Append, "File.AppendAllText");
        File.AppendAllText(path, contents);
    }

    /// <summary><see cref="File.OpenRead(string)"/>, checked.</summary>
    public static FileStream OpenRead(string path)
    {
        Check(path, FileOp.Read, "File.OpenRead");
        return File.OpenRead(path);
    }

    /// <summary><see cref="File.OpenWrite(string)"/>, checked.</summary>
    public static FileStream OpenWrite(string path)
    {
        Check(path, FileOp.Write, "File.OpenWrite");
        return File.OpenWrite(path);
    }

    /// <summary><see cref="File.Create(string)"/>, checked.</summary>
    public static FileStream Create(string path)
    {
        Check(path, FileOp.Write, "File.Create");
        return File.Create(path);
    }

    /// <summary><see cref="File.Open(string, FileMode, FileAccess)"/>, checked as a read only for <c>Open</c> + <c>Read</c>.</summary>
    public static FileStream Open(string path, FileMode mode, FileAccess access = FileAccess.ReadWrite)
    {
        Check(path, OpOf(mode, access), "File.Open");
        return File.Open(path, mode, access);
    }

    /// <summary><see cref="File.Delete(string)"/>, checked.</summary>
    public static void Delete(string path)
    {
        Check(path, FileOp.Delete, "File.Delete");
        File.Delete(path);
    }

    /// <summary><see cref="File.Move(string, string)"/>, both paths checked; the strongest decision wins.</summary>
    public static void Move(string sourceFileName, string destFileName)
    {
        Check(sourceFileName, FileOp.Rename, destFileName, FileOp.Rename, "File.Move");
        File.Move(sourceFileName, destFileName);
    }

    /// <summary><see cref="File.Copy(string, string, bool)"/>, the source checked as a read and the destination as a write; the strongest decision wins.</summary>
    public static void Copy(string sourceFileName, string destFileName, bool overwrite = false)
    {
        Check(sourceFileName, FileOp.Read, destFileName, FileOp.Write, "File.Copy");
        File.Copy(sourceFileName, destFileName, overwrite);
    }
}

/// <summary><see cref="Directory"/> methods with the RASP path check first; see <see cref="RaspFile"/>.</summary>
public static class RaspDirectory
{
    /// <summary><see cref="Directory.GetFiles(string, string)"/>, checked as a listing.</summary>
    public static string[] GetFiles(string path, string searchPattern = "*")
    {
        RaspFile.Check(path, FileOp.List, "Directory.GetFiles");
        return Directory.GetFiles(path, searchPattern);
    }

    /// <summary><see cref="Directory.EnumerateFiles(string, string)"/>, checked as a listing.</summary>
    public static IEnumerable<string> EnumerateFiles(string path, string searchPattern = "*")
    {
        RaspFile.Check(path, FileOp.List, "Directory.EnumerateFiles");
        return Directory.EnumerateFiles(path, searchPattern);
    }

    /// <summary><see cref="Directory.GetDirectories(string, string)"/>, checked as a listing.</summary>
    public static string[] GetDirectories(string path, string searchPattern = "*")
    {
        RaspFile.Check(path, FileOp.List, "Directory.GetDirectories");
        return Directory.GetDirectories(path, searchPattern);
    }

    /// <summary><see cref="Directory.Delete(string, bool)"/>, checked.</summary>
    public static void Delete(string path, bool recursive = false)
    {
        RaspFile.Check(path, FileOp.Delete, "Directory.Delete");
        Directory.Delete(path, recursive);
    }
}
