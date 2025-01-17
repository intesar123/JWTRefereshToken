using JWTRefreshToken.Models;
using Microsoft.AspNetCore.Identity;

namespace JWTRefreshToken.Repositories
{
    public class UserServiceRepository : IUserServiceRepository
    {
        private readonly AppDbContext _context;

        public UserServiceRepository(UserManager<IdentityUser> userManager, AppDbContext context)
        {
            _context = context;
        }

        public UserRefreshTokens AddUserRefreshTokens(UserRefreshTokens user)
        {
            _context.UserRefreshTokens.Add(user);
            _context.SaveChanges();
            return user;
        }

        public void DeleteUserRefreshTokens(string userName, string refreshToken)
        {
            var item = _context.UserRefreshTokens.FirstOrDefault(x =>
                x.UserName == userName && x.RefreshToken == refreshToken
            );
            if (item != null)
            {
                _context.UserRefreshTokens.Remove(item);
                _context.SaveChanges();
            }
        }

        public UserRefreshTokens GetSavedRefreshToken(string UserName, string refreshToken)
        {
            return _context.UserRefreshTokens.FirstOrDefault(x =>
                x.UserName == UserName && x.RefreshToken == refreshToken
            );
        }

        public Task<bool> IsValidUserAsync(UserLogin user)
        {
            var u = _context.UserRegisters.FirstOrDefault(x =>
                x.Email == user.Email && x.Password == user.Password
            );

            if (u != null)
            {
                return Task.FromResult(true);
            }
            else
            {
                return Task.FromResult(false);
            }
        }
    }
}
