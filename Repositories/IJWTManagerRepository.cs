using System.Security.Claims;
using JWTRefreshToken.Models;

namespace JWTRefreshToken.Repositories
{
    public interface IJWTManagerRepository
    {
        Tokens GenerateToken(string userName);
        Tokens GenerateRefreshToken(string userName);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
