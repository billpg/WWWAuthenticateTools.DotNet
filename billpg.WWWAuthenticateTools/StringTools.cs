namespace billpg.WWWAuthenticateTools;

/// <summary>
/// Character-class predicates for the RFC 9110 §11.3 <c>token</c> and
/// <c>token68</c> grammar rules. Grammar validation lives here and is used
/// by the parser and generator; the builder deliberately does not call
/// these, since it trusts values supplied by the calling code rather than
/// re-validating them (see the "current scheme" builder rules).
/// </summary>
internal static class StringTools
{
    /// <summary>
    /// The token characters beyond ASCII alphanumerics, per RFC 9110 §5.6.2:
    /// token = 1*tchar ; tchar = "!" / "#" / "$" / "%" / "&amp;" / "'" / "*" /
    /// "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    /// </summary>
    private static readonly HashSet<char> ExtraTokenChars
        = new(("!#$%&'*+-.^_`|~").ToCharArray());

    /// <summary>
    /// The token68 characters beyond ASCII alphanumerics, per RFC 9110 §11.3:
    /// token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    /// </summary>
    private static readonly HashSet<char> ExtraToken68Chars
        = new(("-._~+/").ToCharArray());

    internal static bool IsAsciiAlphaNumeric(char c)
        => (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9');

    internal static bool IsValidRFC7230Token(string s)
        => s.Length > 0 && s.All(c => IsAsciiAlphaNumeric(c) || ExtraTokenChars.Contains(c));

    internal static bool IsValidToken68(string s)
    {
        if (s.Length == 0)
            return false;

        /* Trailing "=" padding characters are allowed but only at the end. */
        int end = s.Length;
        while (end > 0 && s[end - 1] == '=')
            end--;
        if (end == 0)
            return false;

        for (int i = 0; i < end; i++)
            if (!IsAsciiAlphaNumeric(s[i]) && !ExtraToken68Chars.Contains(s[i]))
                return false;
        return true;
    }
}
