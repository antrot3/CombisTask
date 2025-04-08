using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using ServiceLayer.Interface;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace CombisMVC.Controllers
{
    public class AccountController : Controller
    {
        private readonly IAppUserService _appuserService;

        public AccountController(IAppUserService appuserService)
        {
            _appuserService = appuserService;
        }

        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] UserCreateDto dto)
        {
            if (dto == null)
            {
                return BadRequest("Invalid data.");
            }

            var result = await _appuserService.RegisterAsync(dto);
            return Ok("Registration succes");
        }

        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        public async Task<IActionResult> Login([FromBody] UserLoginDto dto)
        {
            if (dto == null)
            {
                return BadRequest("Invalid data.");
            }

            var token = await _appuserService.LoginAsync(dto);
            if (string.IsNullOrEmpty(token.Value))
            {
                return BadRequest("Invalid credentials.");
            }

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token.Value);
            var claims = jwt.Claims;
            var identity = new ClaimsIdentity(claims, "jwt");
            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            return Ok(new { redirectUrl = Url.Action("Index", "Dashboard") });
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Login");
        }
    }
}
