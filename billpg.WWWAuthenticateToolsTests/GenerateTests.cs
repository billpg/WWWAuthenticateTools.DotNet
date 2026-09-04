using billpg.WWWAuthenticateTools;

namespace billpg.WWWAuthenticateToolsTests;

[TestClass]
public sealed class GenerateTests
{
    [TestMethod]
    public void SchemeOnly()
    {
        var auth = new AuthHeaders().WithScheme("Basic");
        Assert.AreEqual("Basic", auth.ToSingleHeaderValue());
    }

    [TestMethod]
    public void WithToken68()
    {
        var auth = new AuthHeaders().WithScheme("Bearer").WithToken68("Rutabaga123==");
        Assert.AreEqual("Bearer Rutabaga123==", auth.ToSingleHeaderValue());
    }

    [TestMethod]
    public void WithSingleParam_ValidTokenValue_IsUnquoted()
    {
        var auth = new AuthHeaders().WithScheme("Digest").WithParam("realm", "Rutabaga");
        Assert.AreEqual("Digest realm=Rutabaga", auth.ToSingleHeaderValue());
    }

    [TestMethod]
    public void WithMultipleParams_PreservesInsertionOrder()
    {
        var auth = new AuthHeaders()
            .WithScheme("Digest")
            .WithParam("realm", "Rutabaga")
            .WithParam("qop", "auth")
            .WithParam("nonce", "Swede123");

        Assert.AreEqual("Digest realm=Rutabaga, qop=auth, nonce=Swede123", auth.ToSingleHeaderValue());
    }

    [TestMethod]
    public void WithParam_ValueContainingSpace_IsQuoted()
    {
        var auth = new AuthHeaders().WithScheme("Digest").WithParam("realm", "Rutabaga Farms inc");
        Assert.AreEqual("Digest realm=\"Rutabaga Farms inc\"", auth.ToSingleHeaderValue());
    }

    [TestMethod]
    public void WithParam_ValueContainingComma_IsQuoted()
    {
        var auth = new AuthHeaders().WithScheme("Digest").WithParam("realm", "Rutabaga,Swede");
        Assert.AreEqual("Digest realm=\"Rutabaga,Swede\"", auth.ToSingleHeaderValue());
    }

    [TestMethod]
    public void WithParam_ValueContainingQuoteAndBackslash_IsEscaped()
    {
        var auth = new AuthHeaders().WithScheme("Digest").WithParam("realm", "Rutabaga \"prize\" \\turnip\\");
        Assert.AreEqual("Digest realm=\"Rutabaga \\\"prize\\\" \\\\turnip\\\\\"", auth.ToSingleHeaderValue());
    }

    [TestMethod]
    public void ToSingleHeaderValue_JoinsMultipleChallengesWithCommaSpace()
    {
        var auth = new AuthHeaders()
            .WithScheme("HashBack")
            .WithParam("version", "RFC12345")
            .WithScheme("Basic")
            .WithParam("realm", "Rutabaga");

        Assert.AreEqual("HashBack version=RFC12345, Basic realm=Rutabaga", auth.ToSingleHeaderValue());
    }

    [TestMethod]
    public void ToHeaderLines_ReturnsOnePerChallenge()
    {
        var auth = new AuthHeaders()
            .WithScheme("HashBack")
            .WithParam("version", "RFC12345")
            .WithScheme("Basic")
            .WithParam("realm", "Rutabaga");

        var lines = auth.ToHeaderLines().ToList();
        Assert.HasCount(2, lines);
        Assert.AreEqual("HashBack version=RFC12345", lines[0]);
        Assert.AreEqual("Basic realm=Rutabaga", lines[1]);
    }

    [TestMethod]
    public void Token68Challenge_HasNoCommaOrEqualsSign()
    {
        var auth = new AuthHeaders().WithScheme("Bearer").WithToken68("Rutabaga==");
        var headerValue = auth.ToSingleHeaderValue();
        Assert.DoesNotContain(",", headerValue);
    }
}
