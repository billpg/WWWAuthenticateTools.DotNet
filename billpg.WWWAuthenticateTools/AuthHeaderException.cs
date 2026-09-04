namespace billpg.WWWAuthenticateTools;

/// <summary>
/// Base of the shared exception taxonomy. Every exception carries a stable
/// <see cref="Code"/> string, which is the cross-language contract other
/// ports of this library also use — unlike <see cref="Exception.Message"/>,
/// which may be reworded independently per language over time.
/// </summary>
public abstract class AuthHeaderException : Exception
{
    public string Code { get; }

    protected AuthHeaderException(string code, string message) : base(message)
    {
        Code = code;
    }
}

/// <summary>Thrown when input passed to <see cref="ParseHeader.Parse"/> is malformed.</summary>
public sealed class AuthHeaderParseException : AuthHeaderException
{
    /// <summary>Index into the <c>headerLines</c> collection that was being parsed.</summary>
    public int HeaderLineIndex { get; }

    /// <summary>Character offset within that header line where the problem starts.</summary>
    public int CharacterPosition { get; }

    public AuthHeaderParseException(string code, string message, int headerLineIndex, int characterPosition)
        : base(code, message)
    {
        HeaderLineIndex = headerLineIndex;
        CharacterPosition = characterPosition;
    }
}

/// <summary>Thrown on invalid use of the <see cref="AuthHeaders"/> fluent builder.</summary>
public sealed class AuthHeaderBuilderException : AuthHeaderException
{
    public AuthHeaderBuilderException(string code, string message) : base(code, message)
    {
    }
}

/// <summary>The documented, stable error codes shared across all language ports.</summary>
public static class AuthHeaderErrorCodes
{
    public const string NoCurrentScheme = "no_current_scheme";
    public const string DuplicateParam = "duplicate_param";
    public const string Token68ParamConflict = "token68_param_conflict";
    public const string InvalidToken68 = "invalid_token68";
    public const string InvalidAuthParam = "invalid_auth_param";
    public const string UnterminatedQuotedString = "unterminated_quoted_string";
    public const string UnexpectedComma = "unexpected_comma";
}
