using System.Text;

namespace billpg.WWWAuthenticateTools;

/// <summary>
/// Renders an <see cref="AuthHeaders"/> model back to header value text.
/// Always safe to call — unlike parsing, the generator controls every
/// separator itself, so it never has ambiguous input to reject.
/// </summary>
public static class Generate
{
    /// <summary>One header value string per challenge, for adding as separate header instances.</summary>
    public static IEnumerable<string> ToHeaderLines(this AuthHeaders headers)
        => headers.Challenges.Select(ToHeaderLine);

    /// <summary>All challenges joined with ", " into a single header value.</summary>
    public static string ToSingleHeaderValue(this AuthHeaders headers)
        => string.Join(", ", headers.ToHeaderLines());

    private static string ToHeaderLine(Challenge challenge)
    {
        var text = new StringBuilder(challenge.Scheme);
        if (challenge.Token68 != null)
        {
            text.Append(' ').Append(challenge.Token68);
        }
        else if (challenge.Params.Length > 0)
        {
            text.Append(' ');
            bool first = true;
            foreach (var param in challenge.Params)
            {
                if (!first)
                    text.Append(", ");
                first = false;
                text.Append(param.Key).Append('=').Append(FormatParamValue(param.Value));
            }
        }
        return text.ToString();
    }

    private static string FormatParamValue(string value)
        => StringTools.IsValidRFC7230Token(value) ? value : Quote(value);

    private static string Quote(string value)
    {
        var text = new StringBuilder();
        text.Append('"');
        foreach (var c in value)
        {
            if (c == '\\' || c == '"')
                text.Append('\\');
            text.Append(c);
        }
        text.Append('"');
        return text.ToString();
    }
}
