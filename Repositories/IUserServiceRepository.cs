using JWTRefreshToken.Models;

namespace JWTRefreshToken.Repositories
{
    public interface IUserServiceRepository
    {
        Task<bool> IsValidUserAsync(UserLogin user);
        UserRefreshTokens AddUserRefreshTokens(UserRefreshTokens user);
        UserRefreshTokens GetSavedRefreshToken(string UserName, string refreshToken);
        void DeleteUserRefreshTokens(string userName, string refreshToken);
    }
}
