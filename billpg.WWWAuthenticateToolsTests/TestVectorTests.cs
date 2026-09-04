using System.Reflection;
using System.Text.Json;
using billpg.WWWAuthenticateTools;

namespace billpg.WWWAuthenticateToolsTests;

/// <summary>
/// Runs this library against the shared cross-language vectors in the
/// `test-vectors` submodule (billpg/www-authenticate-test-vectors), using
/// the runner logic documented in that repo's README: for each vector, for
/// each of strict/lenient, expect success+equality when that mode is in
/// `validIn`, else expect a throw with the matching error code.
/// </summary>
[TestClass]
public sealed class TestVectorTests
{
    /* MSTest requires [TestMethod] parameters to be public, so these nested
     * records (used only as ParseVector's parameter type) must be public too. */
    public sealed record VectorParam(string Name, string Value);

    public sealed record VectorChallenge(string Scheme, string? Token68, VectorParam[]? Params);

    public sealed record Vector(
        string Id,
        string Category,
        string Direction,
        string[]? Input,
        VectorChallenge[]? Expected,
        string? ExpectedErrorCode,
        string[] ValidIn);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static IEnumerable<object[]> GetParseVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "test-vectors.json");
        var json = File.ReadAllText(path);
        var vectors = JsonSerializer.Deserialize<Vector[]>(json, JsonOptions)
            ?? throw new InvalidOperationException("test-vectors.json deserialized to null.");

        foreach (var vector in vectors.Where(v => v.Direction == "parse"))
        foreach (var strict in new[] { true, false })
            yield return [vector, strict];
    }

    public static string GetDisplayName(MethodInfo methodInfo, object?[] data)
    {
        var vector = (Vector)data[0]!;
        var strict = (bool)data[1]!;
        return $"{vector.Id} (strict={strict})";
    }

    [TestMethod]
    [DynamicData(nameof(GetParseVectors), DynamicDataDisplayName = nameof(GetDisplayName))]
    public void ParseVector(Vector vector, bool strict)
    {
        string mode = strict ? "strict" : "lenient";
        bool shouldPass = vector.ValidIn.Contains(mode);

        if (shouldPass)
        {
            var actual = ParseHeader.Parse(vector.Input!, strict);
            var expected = ToAuthHeaders(vector.Expected!);
            Assert.AreEqual(expected, actual);
        }
        else
        {
            var ex = Assert.ThrowsExactly<AuthHeaderParseException>(
                () => ParseHeader.Parse(vector.Input!, strict));
            Assert.AreEqual(vector.ExpectedErrorCode, ex.Code);
        }
    }

    private static AuthHeaders ToAuthHeaders(VectorChallenge[] challenges)
    {
        var auth = new AuthHeaders();
        foreach (var challenge in challenges)
        {
            auth = auth.WithScheme(challenge.Scheme);
            if (challenge.Token68 is not null)
                auth = auth.WithToken68(challenge.Token68);
            else if (challenge.Params is not null)
                foreach (var param in challenge.Params)
                    auth = auth.WithParam(param.Name, param.Value);
        }
        return auth;
    }
}
