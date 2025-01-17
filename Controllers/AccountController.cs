using JWTRefreshToken.Models;
using JWTRefreshToken.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTRefreshToken.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly IJWTManagerRepository _jWTManager;
    private readonly IUserServiceRepository _userServiceRepository;

    public AccountController(
        IJWTManagerRepository jWTManager,
        IUserServiceRepository userServiceRepository
    )
    {
        _jWTManager = jWTManager;
        _userServiceRepository = userServiceRepository;
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
        var validUser = await _userServiceRepository.IsValidUserAsync(usersdata);

        if (!validUser)
        {
            return Unauthorized("Invalid username or password...");
        }

        var token = _jWTManager.GenerateToken(usersdata.Email);

        if (token == null)
        {
            return Unauthorized("Invalid Attempt..");
        }

        UserRefreshTokens obj = new UserRefreshTokens
        {
            RefreshToken = token.RefreshToken,
            UserName = usersdata.Email,
        };

        _userServiceRepository.AddUserRefreshTokens(obj);
        return Ok(token);
    }

    [AllowAnonymous]
    [HttpPost]
    [Route("refresh-token")]
    public IActionResult Refresh(Tokens token)
    {
        var principal = _jWTManager.GetPrincipalFromExpiredToken(token.AccessToken);
        var username = principal.Identity?.Name;

        var savedRefreshToken = _userServiceRepository.GetSavedRefreshToken(
            username,
            token.RefreshToken
        );

        if (savedRefreshToken.RefreshToken != token.RefreshToken)
        {
            return Unauthorized("Invalid attempt!");
        }

        var newJwtToken = _jWTManager.GenerateRefreshToken(username);

        if (newJwtToken == null)
        {
            return Unauthorized("Invalid attempt!");
        }

        UserRefreshTokens obj = new UserRefreshTokens
        {
            RefreshToken = newJwtToken.RefreshToken,
            UserName = username,
        };

        _userServiceRepository.DeleteUserRefreshTokens(username, token.RefreshToken);
        _userServiceRepository.AddUserRefreshTokens(obj);

        return Ok(newJwtToken);
    }
}
