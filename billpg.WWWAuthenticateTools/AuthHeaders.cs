using System.Collections.Immutable;

namespace billpg.WWWAuthenticateTools;

/// <summary>
/// An ordered, immutable collection of <see cref="Challenge"/> instances —
/// the parsed or built representation of a WWW-Authenticate-family header.
/// Each mutator returns a new instance rather than mutating in place, so a
/// base set of challenges can safely be reused/branched across multiple
/// response paths.
/// </summary>
/// <example>
/// <code>
/// var auth = new AuthHeaders()
///     .WithScheme("HashBack")
///     .WithParam("version", "RFC12345")
///     .WithScheme("Basic")
///     .WithParam("realm", "example");
/// </code>
/// </example>
public sealed class AuthHeaders : IEquatable<AuthHeaders>
{
    public ImmutableArray<Challenge> Challenges { get; }

    public AuthHeaders() : this(ImmutableArray<Challenge>.Empty)
    {
    }

    internal AuthHeaders(ImmutableArray<Challenge> challenges)
    {
        Challenges = challenges;
    }

    /// <summary>Starts a new challenge, which becomes the target of any following <see cref="WithParam"/>/<see cref="WithToken68"/> calls.</summary>
    public AuthHeaders WithScheme(string scheme)
    {
        if (scheme is null)
            throw new ArgumentNullException(nameof(scheme));
        return new AuthHeaders(Challenges.Add(Challenge.Create(scheme)));
    }

    /// <summary>Adds a named parameter to whichever scheme was added most recently.</summary>
    public AuthHeaders WithParam(string name, string value)
    {
        if (name is null)
            throw new ArgumentNullException(nameof(name));
        if (value is null)
            throw new ArgumentNullException(nameof(value));

        var current = CurrentChallengeOrThrow();
        if (current.Token68 != null)
            throw new AuthHeaderBuilderException(
                AuthHeaderErrorCodes.Token68ParamConflict,
                $"Cannot add param '{name}' to scheme '{current.Scheme}': scheme already has a token68 value.");
        if (current.HasParamNamed(name))
            throw new AuthHeaderBuilderException(
                AuthHeaderErrorCodes.DuplicateParam,
                $"Duplicate param '{name}' on scheme '{current.Scheme}'.");

        return new AuthHeaders(Challenges.SetItem(Challenges.Length - 1, current.WithParamCore(name, value)));
    }

    /// <summary>Sets the token68 value of whichever scheme was added most recently.</summary>
    public AuthHeaders WithToken68(string token68)
    {
        if (token68 is null)
            throw new ArgumentNullException(nameof(token68));

        var current = CurrentChallengeOrThrow();
        if (current.Token68 != null || current.Params.Length > 0)
            throw new AuthHeaderBuilderException(
                AuthHeaderErrorCodes.Token68ParamConflict,
                $"Cannot set token68 on scheme '{current.Scheme}': scheme already has {(current.Token68 != null ? "a token68 value" : "named params")}.");

        return new AuthHeaders(Challenges.SetItem(Challenges.Length - 1, current.WithToken68Core(token68)));
    }

    private Challenge CurrentChallengeOrThrow()
    {
        if (Challenges.IsEmpty)
            throw new AuthHeaderBuilderException(
                AuthHeaderErrorCodes.NoCurrentScheme,
                "WithParam/WithToken68 called before any WithScheme.");
        return Challenges[Challenges.Length - 1];
    }

    public bool Equals(AuthHeaders? other)
    {
        if (other is null)
            return false;
        if (ReferenceEquals(this, other))
            return true;
        return Challenges.SequenceEqual(other.Challenges);
    }

    public override bool Equals(object? obj) => Equals(obj as AuthHeaders);

    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            foreach (var c in Challenges)
                hash = (hash * 397) ^ c.GetHashCode();
            return hash;
        }
    }
}
