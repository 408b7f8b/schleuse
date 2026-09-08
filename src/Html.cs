using System.Text;

namespace Schleuse;

/// <summary>
/// Seitengeruest und Maskierung. Es gibt keine Vorlagensprache und kein
/// JavaScript: jede Seite ist eine Zeichenkette, jeder Fremdtext geht durch
/// <see cref="E"/>. Was nicht maskiert wird, faellt beim Lesen sofort auf.
/// </summary>
internal static class Html
{
    /// <summary>Maskiert Text fuer den Fliesstext und fuer Attributwerte.</summary>
    public static string E(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(s.Length + 16);
        foreach (var c in s)
            sb.Append(c switch
            {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&quot;",
                '\'' => "&#39;",
                _ => c.ToString(),
            });
        return sb.ToString();
    }

    public static string Seite(string titel, WebSession? s, string inhalt, string? hinweis = null, string? fehler = null)
    {
        var nav = s is { TotpDone: true }
            ? $"""
               <nav>
                 <a href="/">Overview</a>
                 <a href="/pending">Queue</a>
                 <a href="/devices">Devices</a>
                 <a href="/clients">Access</a>
                 <a href="/users">Users</a>
                 <a href="/tokens">API</a>
                 <span class="sp"></span>
                 <span class="wer">{E(s.User)}{(s.Role == WebRole.Viewer ? " · read only" : "")}</span>
                 <a href="/account">Account</a>
                 <form method="post" action="/logout" class="inline">
                   <input type="hidden" name="csrf" value="{E(s.Csrf)}">
                   <button class="link">sign out</button>
                 </form>
               </nav>
               """
            : "";

        var meldung = "";
        if (fehler is not null) meldung += $"""<p class="fehler">{E(fehler)}</p>""";
        if (hinweis is not null) meldung += $"""<p class="hinweis">{E(hinweis)}</p>""";

        return $"""
            <!doctype html>
            <html lang="en"><head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>{E(titel)} · schleuse</title>
            <style>{Css}</style>
            </head><body>
            <header><a href="/" class="marke">schleuse</a><span class="unter">remote access</span></header>
            {nav}
            <main>{meldung}{inhalt}</main>
            </body></html>
            """;
    }

    const string Css = """
        :root { --bg:#fbfbfa; --fg:#1a1a19; --schwach:#6b6b68; --linie:#e0e0dc;
                --feld:#fff; --akzent:#2d5f8a; --warn:#8a4b2d; --gut:#2d6a4f; }
        @media (prefers-color-scheme: dark) {
          :root { --bg:#16181a; --fg:#e6e6e3; --schwach:#96968f; --linie:#2c2f33;
                  --feld:#1e2124; --akzent:#7fb0dd; --warn:#e0a080; --gut:#7fc9a2; }
        }
        * { box-sizing:border-box; }
        body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
        header { display:flex; align-items:baseline; gap:.6rem; padding:1rem 1.5rem .4rem; }
        .marke { font-weight:650; font-size:1.15rem; color:var(--fg); text-decoration:none; letter-spacing:.02em; }
        .unter { color:var(--schwach); font-size:.85rem; }
        nav { display:flex; align-items:center; gap:1rem; padding:0 1.5rem; border-bottom:1px solid var(--linie);
              flex-wrap:wrap; }
        nav a { color:var(--schwach); text-decoration:none; padding:.5rem 0; border-bottom:2px solid transparent; }
        nav a:hover { color:var(--fg); border-bottom-color:var(--linie); }
        nav .sp { flex:1; }
        nav .wer { color:var(--schwach); font-size:.85rem; }
        main { max-width:62rem; margin:0 auto; padding:1.5rem; }
        h1 { font-size:1.3rem; font-weight:600; margin:0 0 .3rem; }
        h2 { font-size:1.05rem; font-weight:600; margin:1.8rem 0 .6rem; }
        p.lead { color:var(--schwach); margin:0 0 1.4rem; }
        table { border-collapse:collapse; width:100%; margin:.5rem 0 1rem; }
        th { text-align:left; font-weight:600; font-size:.8rem; text-transform:uppercase;
             letter-spacing:.04em; color:var(--schwach); padding:.4rem .6rem; border-bottom:1px solid var(--linie); }
        td { padding:.55rem .6rem; border-bottom:1px solid var(--linie); vertical-align:top; }
        tr:last-child td { border-bottom:none; }
        code, .mono { font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; font-size:.9em; }
        .fp { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:1.05rem; letter-spacing:.06em;
              background:var(--feld); border:1px solid var(--linie); border-radius:4px; padding:.35rem .5rem;
              display:inline-block; }
        form.inline { display:inline; }
        input[type=text], input[type=password], select, textarea {
              background:var(--feld); color:var(--fg); border:1px solid var(--linie); border-radius:4px;
              padding:.45rem .55rem; font:inherit; width:100%; max-width:26rem; }
        input.klein { max-width:11rem; }
        label { display:block; margin:.8rem 0 .25rem; font-size:.85rem; color:var(--schwach); }
        button { background:var(--akzent); color:#fff; border:none; border-radius:4px; padding:.45rem .9rem;
                 font:inherit; cursor:pointer; }
        button.zweit { background:transparent; color:var(--fg); border:1px solid var(--linie); }
        button.gefahr { background:transparent; color:var(--warn); border:1px solid var(--linie); }
        button.link { background:none; border:none; color:var(--schwach); cursor:pointer; padding:0; font:inherit; }
        button.link:hover { color:var(--fg); }
        .fehler { background:color-mix(in srgb, var(--warn) 12%, transparent); border-left:3px solid var(--warn);
                  padding:.6rem .8rem; margin:0 0 1rem; }
        .hinweis { background:color-mix(in srgb, var(--gut) 12%, transparent); border-left:3px solid var(--gut);
                   padding:.6rem .8rem; margin:0 0 1rem; }
        .karte { border:1px solid var(--linie); border-radius:6px; padding:1rem 1.2rem; margin:0 0 1rem;
                 background:var(--feld); }
        .schwach { color:var(--schwach); font-size:.85rem; }
        .an { color:var(--gut); } .aus { color:var(--schwach); }
        .anmelden { max-width:22rem; margin:3rem auto; }
        pre { background:var(--feld); border:1px solid var(--linie); border-radius:4px; padding:.7rem .9rem;
              overflow-x:auto; font-size:.85rem; }
        ul.codes { columns:2; font-family:ui-monospace,Menlo,monospace; list-style:none; padding:0; }
        ul.codes li { padding:.15rem 0; }
        /* Der QR-Code bringt seine eigene weisse Flaeche mit: ein Leser rechnet
           mit dunkel auf hell, auch wenn die Seite dunkel dargestellt wird. */
        p.qr { margin:0 0 1rem; }
        p.qr svg { width:100%; max-width:15rem; height:auto; display:block;
                   border:1px solid var(--linie); border-radius:4px; }
        """;
}
