using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// JWT 인증 설정
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        // 토큰을 발급한 Authorization Server
        options.Authority = "http://localhost:5221";

        // AS에서 Access Token 만들 때 Audience = "api"로 했으니
        options.Audience = "api";

        // 개발 환경이니까 HTTPS 강제 안 함
        options.RequireHttpsMetadata = false;
        //options.MapInboundClaims = false;
        // 필요하면 토큰 검증 이벤트도 걸 수 있음 (지금은 기본값으로 충분)
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// 미들웨어 순서 중요
app.UseAuthentication();
app.UseAuthorization();

// 보호된 API 엔드포인트
app.MapGet("/api/data", (HttpContext ctx) =>
{
    // JWT에서 sub, scope 꺼내기
    //var sub = ctx.User.FindFirst("sub")?.Value;
    var scope = ctx.User.FindFirst("scope")?.Value;
    var sub = ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    // 또는
    //var sub = ctx.User.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;

    if (scope != "api.read")
    {
        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        return ctx.Response.WriteAsync("Insufficient scope");
    }

    var result = new { message = "Protected data", user = sub };
    ctx.Response.ContentType = "application/json";
    return ctx.Response.WriteAsync(JsonSerializer.Serialize(result));
})
.RequireAuthorization(); // 이 엔드포인트는 반드시 인증 필요

app.Run();
