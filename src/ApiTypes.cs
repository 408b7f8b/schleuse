using System.Text.Json.Serialization;

namespace Schleuse;

// ---------------------------------------------------------------------------
// Datenformen der Schnittstelle
//
// Bewusst eine einzige Anfrageform mit lauter freiwilligen Feldern: welche
// davon ein Aufruf braucht, steht in der Beschreibung des jeweiligen Pfades.
// Das haelt die Zahl der Typen klein und damit auch die Zahl der Stellen, an
// denen etwas ungeprueft hereinkommen koennte.
// ---------------------------------------------------------------------------

internal sealed class ApiRequest
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("device")] public string? Device { get; set; }
    [JsonPropertyName("client")] public string? Client { get; set; }
    [JsonPropertyName("user")] public string? User { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("note")] public string? Note { get; set; }
    [JsonPropertyName("role")] public string? Role { get; set; }
    [JsonPropertyName("what")] public string? What { get; set; }
    [JsonPropertyName("services")] public string[]? Services { get; set; }
    [JsonPropertyName("devices")] public string[]? Devices { get; set; }
    [JsonPropertyName("days")] public int? Days { get; set; }
    [JsonPropertyName("enabled")] public bool? Enabled { get; set; }
    [JsonPropertyName("revoked")] public bool? Revoked { get; set; }
}

internal sealed class ApiError
{
    [JsonPropertyName("error")] public string Message { get; set; } = "";
}

internal sealed class ApiOk
{
    [JsonPropertyName("ok")] public bool Ok { get; set; } = true;
    [JsonPropertyName("message")] public string? Message { get; set; }
    /// <summary>Anfangspasswort oder Marke - nur bei der Ausgabe, nie danach.</summary>
    [JsonPropertyName("secret")] public string? Secret { get; set; }
}

internal sealed class ApiTunnel
{
    [JsonPropertyName("client")] public string Client { get; set; } = "";
    [JsonPropertyName("device")] public string Device { get; set; } = "";
    [JsonPropertyName("service")] public string Service { get; set; } = "";
}

internal sealed class ApiStatus
{
    [JsonPropertyName("ui_enabled")] public bool UiEnabled { get; set; }
    [JsonPropertyName("enrollment")] public bool Enrollment { get; set; }
    /// <summary>Ob nur gelistete Geraete sich anmelden duerfen.</summary>
    [JsonPropertyName("device_list_active")] public bool DeviceListActive { get; set; }
    [JsonPropertyName("ca_pin")] public string CaPin { get; set; } = "";
    [JsonPropertyName("relay_listen")] public string RelayListen { get; set; } = "";
    [JsonPropertyName("devices_online")] public int DevicesOnline { get; set; }
    [JsonPropertyName("pending")] public int Pending { get; set; }
    [JsonPropertyName("tunnels")] public ApiTunnel[] Tunnels { get; set; } = [];
}

internal sealed class ApiDevice
{
    [JsonPropertyName("device")] public string Device { get; set; } = "";
    [JsonPropertyName("note")] public string? Note { get; set; }
    /// <summary>Freigegebene Dienste. Fehlt der Eintrag, ist alles freigegeben.</summary>
    [JsonPropertyName("released")] public string[]? Released { get; set; }
    /// <summary>Was das Geraet gerade anbietet - nur bekannt, wenn es verbunden ist.</summary>
    [JsonPropertyName("offered")] public string[] Offered { get; set; } = [];
    [JsonPropertyName("online")] public bool Online { get; set; }
    [JsonPropertyName("online_sec")] public long OnlineSec { get; set; }
    [JsonPropertyName("streams")] public int Streams { get; set; }
    [JsonPropertyName("revoked")] public bool Revoked { get; set; }
}

internal sealed class ApiDevices
{
    [JsonPropertyName("devices")] public ApiDevice[] Devices { get; set; } = [];
}

internal sealed class ApiPendingEntry
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    /// <summary>Muss mit dem uebereinstimmen, den das Geraet beim Anmelden angezeigt hat.</summary>
    [JsonPropertyName("fingerprint")] public string Fingerprint { get; set; } = "";
    [JsonPropertyName("hostname")] public string? Hostname { get; set; }
    [JsonPropertyName("from")] public string From { get; set; } = "";
    [JsonPropertyName("first_seen")] public DateTimeOffset FirstSeen { get; set; }
    [JsonPropertyName("last_seen")] public DateTimeOffset LastSeen { get; set; }
    [JsonPropertyName("state")] public string State { get; set; } = "";
    [JsonPropertyName("proposed")] public Dictionary<string, string> Proposed { get; set; } = new();
    [JsonPropertyName("device")] public string? Device { get; set; }
    [JsonPropertyName("decided_by")] public string? DecidedBy { get; set; }
    [JsonPropertyName("decided_at")] public DateTimeOffset? DecidedAt { get; set; }
}

internal sealed class ApiPending
{
    [JsonPropertyName("requests")] public ApiPendingEntry[] Requests { get; set; } = [];
}

internal sealed class ApiClient
{
    [JsonPropertyName("client")] public string Client { get; set; } = "";
    [JsonPropertyName("devices")] public string[] Devices { get; set; } = [];
    [JsonPropertyName("services")] public string[] Services { get; set; } = [];
    [JsonPropertyName("revoked")] public bool Revoked { get; set; }
}

internal sealed class ApiClients
{
    [JsonPropertyName("clients")] public ApiClient[] Clients { get; set; } = [];
}

internal sealed class ApiUser
{
    [JsonPropertyName("user")] public string User { get; set; } = "";
    [JsonPropertyName("role")] public string Role { get; set; } = "";
    [JsonPropertyName("totp")] public bool Totp { get; set; }
    [JsonPropertyName("recovery_left")] public int RecoveryLeft { get; set; }
    [JsonPropertyName("last_login")] public DateTimeOffset? LastLogin { get; set; }
    [JsonPropertyName("locked_until")] public DateTimeOffset? LockedUntil { get; set; }
    [JsonPropertyName("must_change")] public bool MustChange { get; set; }
}

internal sealed class ApiUsers
{
    [JsonPropertyName("users")] public ApiUser[] Users { get; set; } = [];
}

internal sealed class ApiTokenInfo
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("role")] public string Role { get; set; } = "";
    [JsonPropertyName("created")] public DateTimeOffset Created { get; set; }
    [JsonPropertyName("created_by")] public string CreatedBy { get; set; } = "";
    [JsonPropertyName("expires")] public DateTimeOffset? Expires { get; set; }
    [JsonPropertyName("last_used")] public DateTimeOffset? LastUsed { get; set; }
    [JsonPropertyName("last_from")] public string? LastFrom { get; set; }
}

internal sealed class ApiTokens
{
    [JsonPropertyName("tokens")] public ApiTokenInfo[] Tokens { get; set; } = [];
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ApiRequest))]
[JsonSerializable(typeof(ApiError))]
[JsonSerializable(typeof(ApiOk))]
[JsonSerializable(typeof(ApiStatus))]
[JsonSerializable(typeof(ApiDevices))]
[JsonSerializable(typeof(ApiPending))]
[JsonSerializable(typeof(ApiClients))]
[JsonSerializable(typeof(ApiUsers))]
[JsonSerializable(typeof(ApiTokens))]
internal partial class ApiJson : JsonSerializerContext;
