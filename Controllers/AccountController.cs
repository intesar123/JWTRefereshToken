using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using JWTRefreshToken.Models;
using JWTRefreshToken.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTRefreshToken.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly IJWTManagerRepository _jWTManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    private readonly IUserServiceRepository _userServiceRepository;

    public AccountController(
        IJWTManagerRepository jWTManager,
        IUserServiceRepository userServiceRepository,
        IConfiguration configuration
    )
    {
        _jWTManager = jWTManager;
        _userServiceRepository = userServiceRepository;
        _configuration = configuration;
    }

    [HttpGet]
    public List<string> Get()
    {
        var usersList = new List<string> { "Shubham Chauhan", "Kunal Parmar", "Dipak Kushwaha" };

        return usersList;
    }

    [AllowAnonymous]
    [HttpPost]
    [Route("authenticate-user")]
    public async Task<IActionResult> AuthenticateAsync(UserLogin usersdata)
    {
        var user = await _userManager.FindByEmailAsync(usersdata.Email);

        if (user != null && await _userManager.CheckPasswordAsync(user, usersdata.Password))
        {
            var UserRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            foreach (var userRole in UserRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = _jWTManager.GenerateToken(authClaims);
            var refreshToken = _jWTManager.GenerateRefreshToken();
            _ = int.TryParse(
                _configuration["JWT:RefreshTokenValidityInDays"],
                out int refreshTokenValidityInDays
            );

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

            await _userManager.UpdateAsync(user);

            return Ok(
                new
                {
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken = refreshToken,
                    Expiration = token.ValidTo,
                }
            );
        }

        return Unauthorized();
    }

    [AllowAnonymous]
    [HttpPost]
    [Route("refresh-token")]
    public async Task<IActionResult> Refresh(Tokens token)
    {
        if (token is null)
        {
            return BadRequest("Invalid client request");
        }

        string? accessToken = token.AccessToken;
        string? refreshToken = token.RefreshToken;

        var principal = _jWTManager.GetPrincipalFromExpiredToken(accessToken);
        if (principal is null)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        string username = principal.Identity?.Name;
        var user = await _userManager.FindByNameAsync(username);

        if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
        {
             return BadRequest("Invalid access token or refresh token");
        }

        var newAccessToken = _jWTManager.GenerateToken(principal.Claims.ToList());
        var newRefreshToken = _jWTManager.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        await _userManager.UpdateAsync(user);

        return new ObjectResult(
            new
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                RefreshToken = newRefreshToken,
            }
        );
    }

    [AllowAnonymous]
    [HttpPost]
    [Route("register-user")]
    public async Task<IActionResult> RegisterAsync(UserRegister user)
    {
        var userExists = await _userManager.FindByEmailAsync(user.Email);
        if (userExists != null)
        {
            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "User already exists!" }
            );
        }

        ApplicationUser appUser = new()
        {
            Email = user.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = user.Email,
        };

        var result = await _userManager.CreateAsync(appUser, user.Password);
        if (!result.Succeeded)
        {
            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new Response
                {
                    Status = "Error",
                    Message = "User creation failed! Please check user details and try again.",
                }
            );
        }

        return Ok("User created successfully!");
    }

    [AllowAnonymous]
    [HttpPost]
    [Route("register-admin")]
    public async Task<IActionResult> RegisterAdminAsync(UserRegister user)
    {
        var userExists = await _userManager.FindByEmailAsync(user.Email);
        if (userExists != null)
        {
            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "User already exists!" }
            );
        }

        ApplicationUser appUser = new()
        {
            Email = user.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = user.Email,
        };

        var result = await _userManager.CreateAsync(appUser, user.Password);
        if (!result.Succeeded)
        {
            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new Response
                {
                    Status = "Error",
                    Message = "User creation failed! Please check user details and try again.",
                }
            );
        }

        if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
        {
            await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
        }
        if (!await _roleManager.RoleExistsAsync(UserRoles.User))
        {
            await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
        }

        if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
        {
            await _userManager.AddToRoleAsync(appUser, UserRoles.Admin);
        }

        if (await _roleManager.RoleExistsAsync(UserRoles.User))
        {
            await _userManager.AddToRoleAsync(appUser, UserRoles.User);
        }

        return Ok(new Response { Status = "Success", Message = "User created successfully!" });
    }
}
