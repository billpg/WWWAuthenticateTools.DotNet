using billpg.WWWAuthenticateTools;

namespace billpg.WWWAuthenticateToolsTests;

[TestClass]
public sealed class ParseHeaderTests
{
    [TestMethod]
    public void SchemeOnly()
    {
        var auth = ParseHeader.Parse(["Basic"], strict: true);
        Assert.HasCount(1, auth.Challenges);
        Assert.AreEqual("Basic", auth.Challenges[0].Scheme);
        Assert.IsNull(auth.Challenges[0].Token68);
        Assert.IsEmpty(auth.Challenges[0].Params);
    }

    [TestMethod]
    public void SchemeWithToken68()
    {
        var auth = ParseHeader.Parse(["Bearer Rutabaga123=="], strict: true);
        Assert.AreEqual("Bearer", auth.Challenges[0].Scheme);
        Assert.AreEqual("Rutabaga123==", auth.Challenges[0].Token68);
    }

    [TestMethod]
    public void SchemeWithSingleUnquotedParam()
    {
        var auth = ParseHeader.Parse(["Digest realm=Rutabaga"], strict: true);
        Assert.AreEqual("Digest", auth.Challenges[0].Scheme);
        Assert.AreEqual("realm", auth.Challenges[0].Params[0].Key);
        Assert.AreEqual("Rutabaga", auth.Challenges[0].Params[0].Value);
    }

    [TestMethod]
    public void SchemeWithMultipleParams_CommaSeparated()
    {
        var auth = ParseHeader.Parse(["Digest realm=Rutabaga, qop=auth, nonce=Swede123"], strict: true);
        Assert.AreEqual("Digest", auth.Challenges[0].Scheme);
        Assert.HasCount(3, auth.Challenges[0].Params);
        Assert.AreEqual("realm", auth.Challenges[0].Params[0].Key);
        Assert.AreEqual("qop", auth.Challenges[0].Params[1].Key);
        Assert.AreEqual("nonce", auth.Challenges[0].Params[2].Key);
    }

    [TestMethod]
    public void QuotedValue_WithEscapedQuoteAndBackslash()
    {
        var auth = ParseHeader.Parse(["Digest realm=\"Rutabaga \\\"prize\\\" \\\\turnip\\\\\""], strict: true);
        Assert.AreEqual("Rutabaga \"prize\" \\turnip\\", auth.Challenges[0].Params[0].Value);
    }

    [TestMethod]
    public void MultipleChallenges_InOneLine()
    {
        var auth = ParseHeader.Parse(["HashBack version=RFC12345, Basic realm=Rutabaga"], strict: true);
        Assert.HasCount(2, auth.Challenges);
        Assert.AreEqual("HashBack", auth.Challenges[0].Scheme);
        Assert.AreEqual("version", auth.Challenges[0].Params[0].Key);
        Assert.AreEqual("Basic", auth.Challenges[1].Scheme);
        Assert.AreEqual("realm", auth.Challenges[1].Params[0].Key);
    }

    [TestMethod]
    public void MultipleHeaderLines_EachParsedIndependently()
    {
        var auth = ParseHeader.Parse(["Basic realm=Rutabaga", "Digest realm=Swede"], strict: true);
        Assert.HasCount(2, auth.Challenges);
        Assert.AreEqual("Basic", auth.Challenges[0].Scheme);
        Assert.AreEqual("Digest", auth.Challenges[1].Scheme);
    }

    [TestMethod]
    public void RoundTrip_BuildThenGenerateThenParse_ProducesEqualModel()
    {
        var built = new AuthHeaders()
            .WithScheme("HashBack")
            .WithParam("version", "RFC12345")
            .WithScheme("Digest")
            .WithParam("realm", "Rutabaga Farms inc")
            .WithScheme("Bearer")
            .WithToken68("Swede123==");

        var parsedBack = ParseHeader.Parse([built.ToSingleHeaderValue()], strict: true);

        Assert.AreEqual(built, parsedBack);
    }

    [TestMethod]
    public void DuplicateParamName_ThrowsDuplicateParam()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderParseException>(
            () => ParseHeader.Parse(["Digest realm=Rutabaga, realm=Swede"], strict: true));
        Assert.AreEqual(AuthHeaderErrorCodes.DuplicateParam, ex.Code);
    }

    [TestMethod]
    public void TrailingComma_ThrowsUnexpectedComma()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderParseException>(
            () => ParseHeader.Parse(["Digest realm=\"Rutabaga\", nonce=\"Swede\","], strict: true));
        Assert.AreEqual(AuthHeaderErrorCodes.UnexpectedComma, ex.Code);
    }

    [TestMethod]
    public void InvalidToken68Characters_ThrowsInvalidToken68()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderParseException>(
            () => ParseHeader.Parse(["Bearer Rutabaga@Swede"], strict: true));
        Assert.AreEqual(AuthHeaderErrorCodes.InvalidToken68, ex.Code);
    }

    [TestMethod]
    public void UnterminatedQuotedString_Throws()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderParseException>(
            () => ParseHeader.Parse(["Digest realm=\"Rutabaga"], strict: true));
        Assert.AreEqual(AuthHeaderErrorCodes.UnterminatedQuotedString, ex.Code);
    }

    [TestMethod]
    public void AuthParamBeforeAnyScheme_ThrowsInvalidAuthParam()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderParseException>(
            () => ParseHeader.Parse(["realm=Rutabaga"], strict: true));
        Assert.AreEqual(AuthHeaderErrorCodes.InvalidAuthParam, ex.Code);
    }

    [TestMethod]
    public void ControlCharacterInQuotedString_Strict_ThrowsInvalidAuthParam()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderParseException>(
            () => ParseHeader.Parse(["Digest realm=\"Ruta\rbaga\""], strict: true));
        Assert.AreEqual(AuthHeaderErrorCodes.InvalidAuthParam, ex.Code);
    }

    [TestMethod]
    public void EscapedControlCharacterInQuotedString_Strict_ThrowsInvalidAuthParam()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderParseException>(
            () => ParseHeader.Parse(["Digest realm=\"Ruta\\\rbaga\""], strict: true));
        Assert.AreEqual(AuthHeaderErrorCodes.InvalidAuthParam, ex.Code);
    }

    [TestMethod]
    public void ControlCharacterInQuotedString_Lenient_IsReplacedWithSpace()
    {
        var auth = ParseHeader.Parse(["Digest realm=\"Ruta\rbaga\""], strict: false);
        Assert.AreEqual("Ruta baga", auth.Challenges[0].Params[0].Value);
    }

    [TestMethod]
    public void HeaderInjectionAttemptInQuotedString_Lenient_CannotSmuggleAHeaderLine()
    {
        var auth = ParseHeader.Parse(["Digest realm=\"Rutabaga\r\nInjected: header\""], strict: false);
        var value = auth.Challenges[0].Params[0].Value;
        Assert.DoesNotContain("\r", value);
        Assert.DoesNotContain("\n", value);
    }

    [TestMethod]
    public void HorizontalTabBetweenItems_Strict_IsAccepted()
    {
        var auth = ParseHeader.Parse(["Digest\trealm=Rutabaga,\tqop=auth"], strict: true);
        Assert.AreEqual("realm", auth.Challenges[0].Params[0].Key);
        Assert.AreEqual("qop", auth.Challenges[0].Params[1].Key);
    }
}
