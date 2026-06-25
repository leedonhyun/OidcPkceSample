using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();

var app = builder.Build();
app.UseSession();

Dictionary<string, string> authorizationCodes = new(); // code → code_challenge 저장
Dictionary<string, string> accessTokens = new();       // access_token → user

string Base64UrlEncode(byte[] input) =>
    Convert.ToBase64String(input).Replace("+", "-").Replace("/", "_").Replace("=", "");

// 1) Authorization Endpoint
app.MapGet("/authorize", async ctx =>
{
    var responseType = ctx.Request.Query["response_type"];
    var clientId = ctx.Request.Query["client_id"];
    var redirectUri = ctx.Request.Query["redirect_uri"];
    var state = ctx.Request.Query["state"];
    var codeChallenge = ctx.Request.Query["code_challenge"];
    var codeChallengeMethod = ctx.Request.Query["code_challenge_method"];

    // 간단한 로그인 화면 표시
    await ctx.Response.WriteAsync($@"
        <html>
        <body>
            <h2>Authorization Server Login</h2>
            <form method='post' action='/login'>
                <input type='hidden' name='redirect_uri' value='{redirectUri}' />
                <input type='hidden' name='state' value='{state}' />
                <input type='hidden' name='code_challenge' value='{codeChallenge}' />
                <input type='hidden' name='client_id' value='{clientId}' />
                <button type='submit'>Login as test-user</button>
            </form>
        </body>
        </html>
    ");
});

// 2) 로그인 처리 → Authorization Code 발급
app.MapPost("/login", async ctx =>
{
    var form = ctx.Request.Form;
    var redirectUri = form["redirect_uri"];
    var state = form["state"];
    var codeChallenge = form["code_challenge"];

    var code = Guid.NewGuid().ToString("N");

    authorizationCodes[code] = codeChallenge;

    ctx.Response.Redirect($"{redirectUri}?code={code}&state={state}");
});

// 3) Token Endpoint
app.MapPost("/token", async ctx =>
{
    var form = await ctx.Request.ReadFormAsync();

    var code = form["code"];
    var codeVerifier = form["code_verifier"];
    var redirectUri = form["redirect_uri"];

    if (!authorizationCodes.TryGetValue(code!, out var savedCodeChallenge))
    {
        await ctx.Response.WriteAsync("Invalid code");
        return;
    }

    // PKCE 검증
    using var sha = SHA256.Create();
    var computed = Base64UrlEncode(sha.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier!)));

    if (computed != savedCodeChallenge)
    {
        await ctx.Response.WriteAsync("Invalid PKCE");
        return;
    }

    // Access Token & ID Token 발급
    var accessToken = Guid.NewGuid().ToString("N");
    accessTokens[accessToken] = "test-user";

    var idToken = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"sub\":\"test-user\"}")) + "." +
                  Base64UrlEncode(Encoding.UTF8.GetBytes("{}")) + "." +
                  Base64UrlEncode(Encoding.UTF8.GetBytes("signature"));

    var json = JsonSerializer.Serialize(new
    {
        access_token = accessToken,
        id_token = idToken,
        token_type = "Bearer",
        expires_in = 3600
    });

    ctx.Response.ContentType = "application/json";
    await ctx.Response.WriteAsync(json);
});

// 4) UserInfo Endpoint
app.MapGet("/userinfo", async ctx =>
{
    var auth = ctx.Request.Headers["Authorization"].ToString();
    if (!auth.StartsWith("Bearer "))
    {
        ctx.Response.StatusCode = 401;
        return;
    }

    var token = auth.Substring("Bearer ".Length);

    if (!accessTokens.TryGetValue(token, out var user))
    {
        ctx.Response.StatusCode = 401;
        return;
    }

    var json = JsonSerializer.Serialize(new { sub = user, name = "Test User" });
    ctx.Response.ContentType = "application/json";
    await ctx.Response.WriteAsync(json);
});

app.Run();
