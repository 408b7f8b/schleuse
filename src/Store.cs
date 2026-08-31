using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Schleuse;

/// <summary>
/// Zustandsdateien des Relays (Tokens, Benutzer) - klein, selten geschrieben,
/// aber sie duerfen einen Stromausfall mitten im Schreiben nicht als halbe
/// Datei ueberleben. Darum immer: neben die Zieldatei schreiben, auf die Platte
/// zwingen, umbenennen. Das Umbenennen ist unteilbar.
/// </summary>
internal static class Store
{
    public static T Load<T>(string path, JsonTypeInfo<T> ti, Func<T> leer) where T : class
    {
        if (!File.Exists(path)) return leer();
        var text = File.ReadAllText(path);
        if (text.Trim().Length == 0) return leer();
        return JsonSerializer.Deserialize(text, ti) ?? leer();
    }

    public static void Save<T>(string path, T wert, JsonTypeInfo<T> ti)
    {
        var tmp = path + ".neu";
        var bytes = JsonSerializer.SerializeToUtf8Bytes(wert, ti);
        using (var f = new FileStream(tmp, new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        }))
        {
            f.Write(bytes);
            f.Flush(flushToDisk: true);
        }
        File.Move(tmp, path, overwrite: true);
    }
}
