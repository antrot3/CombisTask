using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace CombisMVC.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUserService _userService;

        public AccountController(IUserService userService)
        {
            _userService = userService;
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

            var result = await _userService.RegisterAsync(dto);
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

            var token = await _userService.LoginAsync(dto);
            if (string.IsNullOrEmpty(token))
            {
                return BadRequest("Invalid credentials.");
            }

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            var claims = jwt.Claims;
            var identity = new ClaimsIdentity(claims, "jwt");
            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            // Return OK with a redirect URL; alternatively, perform a server-side redirect
            return Ok(new { redirectUrl = Url.Action("Index", "Dashboard") });
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Login");
        }
    }
}
