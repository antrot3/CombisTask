using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using Microsoft.AspNet.Identity;
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

            var result = await _appuserService.LoginUserToAppAsync(dto);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Value.Principal);

            if (result.Value.User.Role == "Administrator")
                return Ok(new { redirectUrl = Url.Action("Index", "Dashboard") });
            else if (result.Value.User.Role == "Klijent")
            {
                return Ok(new { redirectUrl = Url.Action("Klijent", "Dashboard", new { id = result.Value.User.Id }) });
            }

            return BadRequest("Unsupported role.");
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Login");
        }
    }
}
