using billpg.WWWAuthenticateTools;

namespace billpg.WWWAuthenticateToolsTests;

[TestClass]
public sealed class BuilderTests
{
    [TestMethod]
    public void HappyPath_ParamsAttachToMostRecentScheme()
    {
        var auth = new AuthHeaders()
            .WithScheme("HashBack")
            .WithParam("version", "RFC12345")
            .WithScheme("Basic")
            .WithParam("realm", "Rutabaga Farms inc");

        Assert.HasCount(2, auth.Challenges);

        Assert.AreEqual("HashBack", auth.Challenges[0].Scheme);
        Assert.HasCount(1, auth.Challenges[0].Params);
        Assert.AreEqual("version", auth.Challenges[0].Params[0].Key);
        Assert.AreEqual("RFC12345", auth.Challenges[0].Params[0].Value);

        Assert.AreEqual("Basic", auth.Challenges[1].Scheme);
        Assert.HasCount(1, auth.Challenges[1].Params);
        Assert.AreEqual("realm", auth.Challenges[1].Params[0].Key);
        Assert.AreEqual("Rutabaga Farms inc", auth.Challenges[1].Params[0].Value);
    }

    [TestMethod]
    public void HappyPath_WithToken68()
    {
        var auth = new AuthHeaders().WithScheme("Bearer").WithToken68("Rutabaga123==");
        Assert.AreEqual("Rutabaga123==", auth.Challenges[0].Token68);
    }

    [TestMethod]
    public void WithParam_BeforeAnyScheme_ThrowsNoCurrentScheme()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderBuilderException>(
            () => new AuthHeaders().WithParam("realm", "Rutabaga"));
        Assert.AreEqual(AuthHeaderErrorCodes.NoCurrentScheme, ex.Code);
    }

    [TestMethod]
    public void WithToken68_BeforeAnyScheme_ThrowsNoCurrentScheme()
    {
        var ex = Assert.ThrowsExactly<AuthHeaderBuilderException>(
            () => new AuthHeaders().WithToken68("Rutabaga"));
        Assert.AreEqual(AuthHeaderErrorCodes.NoCurrentScheme, ex.Code);
    }

    [TestMethod]
    public void WithParam_DuplicateName_ThrowsDuplicateParam()
    {
        var auth = new AuthHeaders().WithScheme("Digest").WithParam("realm", "Rutabaga");
        var ex = Assert.ThrowsExactly<AuthHeaderBuilderException>(
            () => auth.WithParam("realm", "Swede"));
        Assert.AreEqual(AuthHeaderErrorCodes.DuplicateParam, ex.Code);
    }

    [TestMethod]
    public void WithParam_DuplicateName_IsCaseInsensitive()
    {
        var auth = new AuthHeaders().WithScheme("Digest").WithParam("realm", "Rutabaga");
        var ex = Assert.ThrowsExactly<AuthHeaderBuilderException>(
            () => auth.WithParam("REALM", "Swede"));
        Assert.AreEqual(AuthHeaderErrorCodes.DuplicateParam, ex.Code);
    }

    [TestMethod]
    public void WithParam_AfterWithToken68_ThrowsToken68ParamConflict()
    {
        var auth = new AuthHeaders().WithScheme("Bearer").WithToken68("Rutabaga");
        var ex = Assert.ThrowsExactly<AuthHeaderBuilderException>(
            () => auth.WithParam("realm", "Swede"));
        Assert.AreEqual(AuthHeaderErrorCodes.Token68ParamConflict, ex.Code);
    }

    [TestMethod]
    public void WithToken68_AfterWithParam_ThrowsToken68ParamConflict()
    {
        var auth = new AuthHeaders().WithScheme("Digest").WithParam("realm", "Rutabaga");
        var ex = Assert.ThrowsExactly<AuthHeaderBuilderException>(
            () => auth.WithToken68("Swede"));
        Assert.AreEqual(AuthHeaderErrorCodes.Token68ParamConflict, ex.Code);
    }

    [TestMethod]
    public void WithToken68_CalledTwice_ThrowsToken68ParamConflict()
    {
        var auth = new AuthHeaders().WithScheme("Bearer").WithToken68("Rutabaga");
        var ex = Assert.ThrowsExactly<AuthHeaderBuilderException>(
            () => auth.WithToken68("Swede"));
        Assert.AreEqual(AuthHeaderErrorCodes.Token68ParamConflict, ex.Code);
    }

    [TestMethod]
    public void Mutators_ReturnNewInstances_BaseUnchanged()
    {
        var basic = new AuthHeaders().WithScheme("Basic");
        var withRealm = basic.WithParam("realm", "Rutabaga");

        Assert.IsEmpty(basic.Challenges[0].Params);
        Assert.HasCount(1, withRealm.Challenges[0].Params);
    }
}
