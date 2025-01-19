using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JWTRefreshToken.Models;

namespace JWTRefreshToken.Repositories
{
    public interface IJWTManagerRepository
    {
        JwtSecurityToken GenerateToken(List<Claim> authClaims);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
