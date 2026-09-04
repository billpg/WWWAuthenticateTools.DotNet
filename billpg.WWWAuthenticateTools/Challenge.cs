using System.Collections.Immutable;

namespace billpg.WWWAuthenticateTools;

/// <summary>
/// A single <c>auth-scheme [ token68 | #auth-param ]</c> challenge from a
/// WWW-Authenticate-family header. Immutable; construct and modify via the
/// <see cref="AuthHeaders"/> fluent builder or <see cref="ParseHeader"/>.
/// </summary>
public sealed class Challenge : IEquatable<Challenge>
{
    public string Scheme { get; }
    public string? Token68 { get; }

    /// <summary>
    /// Ordered name/value pairs, kept in insertion order for round-tripping.
    /// Mutually exclusive with <see cref="Token68"/>. Names are logically
    /// case-insensitive and unique per challenge, though the original casing
    /// is preserved here.
    /// </summary>
    public ImmutableArray<KeyValuePair<string, string>> Params { get; }

    private Challenge(string scheme, string? token68, ImmutableArray<KeyValuePair<string, string>> parameters)
    {
        Scheme = scheme;
        Token68 = token68;
        Params = parameters;
    }

    internal static Challenge Create(string scheme)
        => new(scheme, null, ImmutableArray<KeyValuePair<string, string>>.Empty);

    internal Challenge WithToken68Core(string token68)
        => new(Scheme, token68, Params);

    internal Challenge WithParamCore(string name, string value)
        => new(Scheme, Token68, Params.Add(new KeyValuePair<string, string>(name, value)));

    internal bool HasParamNamed(string name)
        => Params.Any(p => string.Equals(p.Key, name, StringComparison.OrdinalIgnoreCase));

    public bool Equals(Challenge? other)
    {
        if (other is null)
            return false;
        if (ReferenceEquals(this, other))
            return true;
        return string.Equals(Scheme, other.Scheme, StringComparison.OrdinalIgnoreCase)
            && Token68 == other.Token68
            && Params.SequenceEqual(other.Params);
    }

    public override bool Equals(object? obj) => Equals(obj as Challenge);

    public override int GetHashCode()
    {
        /* netstandard2.0 lacks System.HashCode, so combine manually. */
        unchecked
        {
            int hash = StringComparer.OrdinalIgnoreCase.GetHashCode(Scheme);
            hash = (hash * 397) ^ (Token68?.GetHashCode() ?? 0);
            foreach (var p in Params)
            {
                hash = (hash * 397) ^ StringComparer.OrdinalIgnoreCase.GetHashCode(p.Key);
                hash = (hash * 397) ^ p.Value.GetHashCode();
            }
            return hash;
        }
    }
}
