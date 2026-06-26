using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"C:\temp\keys"))
    .SetApplicationName("OidcPkceSample");

var app = builder.Build();
app.UseSession();

var keyPath = "rsa_key.xml";
RSA rsa;

if (File.Exists(keyPath))
{
    rsa = RSA.Create();
    rsa.FromXmlString(File.ReadAllText(keyPath));
}
else
{
    rsa = RSA.Create(2048);
    File.WriteAllText(keyPath, rsa.ToXmlString(true));
}
Dictionary<string, string> authorizationCodes = new(); // code → code_challenge 저장
Dictionary<string, string> accessTokens = new();       // access_token → user

// string Base64UrlEncode(byte[] input) =>
//     Convert.ToBase64String(input).Replace("+", "-").Replace("/", "_").Replace("=", "");

// var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("THIS_IS_A_SUPER_LONG_64_BYTE_SECRET_KEY_FOR_HS256_SECURITY_123456"));
// var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
//using var rsa = RSA.Create(2048);
var rsaKey = new RsaSecurityKey(rsa)
{
    KeyId = Guid.NewGuid().ToString("N")
};

var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

string issuer = "http://localhost:5221";
string audience = "YOUR_CLIENT_ID";

app.MapGet("/jwks", async ctx =>
{
    var parameters = rsa.ExportParameters(false);

    if (parameters.Exponent == null || parameters.Modulus == null)
        throw new Exception("RSA key parameters are missing.");

    var e = Convert.ToBase64String(parameters.Exponent);
    var n = Convert.ToBase64String(parameters.Modulus);

    var jwk = new
    {
        kty = "RSA",
        use = "sig",
        kid = rsaKey.KeyId,
        alg = "RS256",
        e = e,
        n = n
    };

    var jwks = new
    {
        keys = new[] { jwk }
    };

    ctx.Response.ContentType = "application/json";
    await ctx.Response.WriteAsync(JsonSerializer.Serialize(jwks));
});
app.MapGet("/.well-known/openid-configuration", async ctx =>
{
    var config = new
    {
        issuer = issuer,
        jwks_uri = $"{issuer}/jwks",
        authorization_endpoint = $"{issuer}/authorize",
        token_endpoint = $"{issuer}/token",
        userinfo_endpoint = $"{issuer}/userinfo",
        response_types_supported = new[] { "code" },
        subject_types_supported = new[] { "public" },
        id_token_signing_alg_values_supported = new[] { "RS256" },
        token_endpoint_auth_methods_supported = new[] { "client_secret_post" }
    };

    ctx.Response.ContentType = "application/json";
    await ctx.Response.WriteAsync(JsonSerializer.Serialize(config));
});

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
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsync("Invalid code");
        return;
    }
    using var sha = SHA256.Create();
    //var computed = Convert.ToBase64String(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier!)));
    var hash = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier!));
    var computed = Base64UrlEncode(hash);
    if (computed != savedCodeChallenge)
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsync("Invalid PKCE");
        return;
    }
    // // PKCE 검증
    // using var sha = SHA256.Create();
    // var computed = Base64UrlEncode(sha.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier!)));

    // if (computed != savedCodeChallenge)
    // {
    //     await ctx.Response.WriteAsync("Invalid PKCE");
    //     return;
    // }

    // Access Token & ID Token 발급
    // var accessToken = Guid.NewGuid().ToString("N");
    // accessTokens[accessToken] = "test-user";

    // var idToken = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"sub\":\"test-user\"}")) + "." +
    //               Base64UrlEncode(Encoding.UTF8.GetBytes("{}")) + "." +
    //               Base64UrlEncode(Encoding.UTF8.GetBytes("signature"));

    // var json = JsonSerializer.Serialize(new
    // {
    //     access_token = accessToken,
    //     id_token = idToken,
    //     token_type = "Bearer",
    //     expires_in = 3600
    // });

    // ctx.Response.ContentType = "application/json";
    // await ctx.Response.WriteAsync(json);

    // Access Token (JWT) 생성
    var accessTokenHandler = new JwtSecurityTokenHandler();
    var accessTokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", "test-user"),
            new Claim("scope", "api.read")
        }),
        Expires = DateTime.UtcNow.AddMinutes(30),
        Issuer = issuer,
        Audience = "api",
        SigningCredentials = signingCredentials
    };

    var accessTokenSecurity = accessTokenHandler.CreateToken(accessTokenDescriptor);
    var accessToken = accessTokenHandler.WriteToken(accessTokenSecurity);

    accessTokenHandler.WriteToken(accessTokenSecurity);

    // ID Token (JWT) 생성
    var idTokenHandler = new JwtSecurityTokenHandler();
    var idTokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "test-user"),
            new Claim(JwtRegisteredClaimNames.Iss, issuer),
            new Claim(JwtRegisteredClaimNames.Aud, audience),
        }),
        Expires = DateTime.UtcNow.AddMinutes(30),
        Issuer = issuer,
        Audience = audience,
        SigningCredentials = signingCredentials
    };

    var idTokenSecurity = idTokenHandler.CreateToken(idTokenDescriptor);
    var idToken = idTokenHandler.WriteToken(idTokenSecurity);

    //     // JWT ID Token 생성
    //     var claims = new[]
    // {
    //     new Claim(JwtRegisteredClaimNames.Sub, "test-user"),
    //     new Claim(JwtRegisteredClaimNames.Iss, issuer),
    //     new Claim(JwtRegisteredClaimNames.Aud, audience),
    //     new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
    // };

    //     var tokenDescriptor = new SecurityTokenDescriptor
    //     {
    //         Subject = new ClaimsIdentity(claims),
    //         Expires = DateTime.UtcNow.AddMinutes(30),
    //         SigningCredentials = signingCredentials,
    //         Issuer = issuer,
    //         Audience = audience
    //     };

    //     var tokenHandler = new JwtSecurityTokenHandler();
    //     var securityToken = tokenHandler.CreateToken(tokenDescriptor);
    //     var idToken = tokenHandler.WriteToken(securityToken);

    var json = JsonSerializer.Serialize(new
    {
        access_token = accessToken,
        id_token = idToken,
        token_type = "Bearer",
        expires_in = 3600
    });

    ctx.Response.ContentType = "application/json";
    await ctx.Response.WriteAsync(json);
    
    string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }


});
app.MapGet("/api/data", async ctx =>
{
    var auth = ctx.Request.Headers["Authorization"].ToString();
    if (!auth.StartsWith("Bearer "))
    {
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsync("Missing bearer token");
        return;
    }

    var token = auth.Substring("Bearer ".Length);

    var tokenHandler = new JwtSecurityTokenHandler();
    var validationParameters = new TokenValidationParameters
    {
        ValidIssuer = issuer,
        ValidAudience = "api",
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = rsaKey
    };

    try
    {
        var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

        var sub = principal.FindFirst("sub")?.Value;
        var scope = principal.FindFirst("scope")?.Value;

        if (scope != "api.read")
        {
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsync("Insufficient scope");
            return;
        }

        var result = new { message = "Protected data", user = sub };
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(result));
    }
    catch (Exception ex)
    {
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsync("Invalid token: " + ex.Message);
    }
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
