using Microsoft.IdentityModel.Tokens;

public class SigningKeyInfo
{
    public RsaSecurityKey Key { get; set; } = default!;
    public bool IsActive { get; set; }
}