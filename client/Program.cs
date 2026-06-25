using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Extensions;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"C:\temp\keys"))
    .SetApplicationName("OidcPkceSample");;
var app = builder.Build();
app.UseSession();

string clientId = "YOUR_CLIENT_ID";
string clientSecret = "YOUR_CLIENT_SECRET"; // 공개 클라이언트면 생략
string redirectUri = "http://localhost:5077/callback";
string authorizeEndpoint = "http://localhost:5221/authorize";
string tokenEndpoint = "http://localhost:5221/token";

// PKCE 유틸
string Base64UrlEncode(byte[] input) =>
    Convert.ToBase64String(input).Replace("+", "-").Replace("/", "_").Replace("=", "");

string GenerateCodeVerifier()
{
    var bytes = RandomNumberGenerator.GetBytes(32);
    return Base64UrlEncode(bytes);
}

string GenerateCodeChallenge(string verifier)
{
    using var sha = SHA256.Create();
    return Base64UrlEncode(sha.ComputeHash(Encoding.UTF8.GetBytes(verifier)));
}

// 1) 로그인 시작
app.MapGet("/login", async ctx =>
{
    var codeVerifier = GenerateCodeVerifier();
    var codeChallenge = GenerateCodeChallenge(codeVerifier);

    ctx.Session.SetString("code_verifier", codeVerifier);

    var state = Guid.NewGuid().ToString();
    var nonce = Guid.NewGuid().ToString();

    ctx.Session.SetString("state", state);
    ctx.Session.SetString("nonce", nonce);

    var url = $"{authorizeEndpoint}" +
              $"?response_type=code" +
              $"&client_id={Uri.EscapeDataString(clientId)}" +
              $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
              $"&scope={Uri.EscapeDataString("openid profile email")}" +
              $"&state={Uri.EscapeDataString(state)}" +
              $"&nonce={Uri.EscapeDataString(nonce)}" +
              $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
              $"&code_challenge_method=S256";

    ctx.Response.Redirect(url);
});

// 2) 콜백 처리
app.MapGet("/callback", async ctx =>
{
    // var code = ctx.Request.Query["code"].ToString();
    // var state = ctx.Request.Query["state"].ToString();

    // var savedState = ctx.Session.GetString("state");
    // if (state != savedState)
    // {
    //     await ctx.Response.WriteAsync("Invalid state");
    //     return;
    // }

    // var codeVerifier = ctx.Session.GetString("code_verifier");

    // var form = new Dictionary<string, string>
    // {
    //     ["grant_type"] = "authorization_code",
    //     ["code"] = code,
    //     ["redirect_uri"] = redirectUri,
    //     ["client_id"] = clientId,
    //     ["code_verifier"] = codeVerifier
    // };

    // if (!string.IsNullOrEmpty(clientSecret))
    //     form["client_secret"] = clientSecret;

    // using var http = new HttpClient();
    // var res = await http.PostAsync(tokenEndpoint, new FormUrlEncodedContent(form));
    // var json = await res.Content.ReadAsStringAsync();

    // await ctx.Response.WriteAsync("Token Response:\n" + json);
     var code = ctx.Request.Query["code"].ToString();
    var state = ctx.Request.Query["state"].ToString();

    var savedState = ctx.Session.GetString("state");
    if (state != savedState)
    {
        await ctx.Response.WriteAsync("Invalid state");
        return;
    }

    var codeVerifier = ctx.Session.GetString("code_verifier");

    var tokenEndpoint = "http://localhost:5221/token"; // AuthorizationServer 주소
    var form = new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code",
        ["code"] = code,
        ["redirect_uri"] = "https://localhost:5077/callback",
        ["client_id"] = clientId,
        ["code_verifier"] = codeVerifier
    };

    if (!string.IsNullOrEmpty(clientSecret))
        form["client_secret"] = clientSecret;

    using var httpClient = new HttpClient();
    var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(form));
    var json = await response.Content.ReadAsStringAsync();

    // 간단 파싱 (실제로는 JsonDocument 사용 권장)
    using var doc = JsonDocument.Parse(json);
    var idToken = doc.RootElement.GetProperty("id_token").GetString();

    // JWT 검증
    var tokenHandler = new JwtSecurityTokenHandler();
    var validationParameters = new TokenValidationParameters
    {
        ValidIssuer = "http://localhost:5221",
        ValidAudience = clientId,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("THIS_IS_A_SUPER_LONG_64_BYTE_SECRET_KEY_FOR_HS256_SECURITY_123456")),
        ValidateIssuerSigningKey = true,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(2)
    };

    try
    {
        var principal = tokenHandler.ValidateToken(idToken, validationParameters, out var validatedToken);

        var sub = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        await ctx.Response.WriteAsync($"Login success! user = {sub}\n\nRaw Token Response:\n{json}");
    }
    catch (Exception ex)
    {
        await ctx.Response.WriteAsync("Invalid ID Token: " + ex.Message);
    }
});

app.MapGet("/", () => "OIDC + PKCE Sample Running. Go to /login");

app.Run();
