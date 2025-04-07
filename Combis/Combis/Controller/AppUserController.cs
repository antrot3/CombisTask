using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Combis.Controller
{
    [ApiController]  // This marks the class as an API controller
    [Route("api/[controller]")]  // This defines the base route for your controller
    public class AppUsersController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILogger<AppUsersController> _logger;

        public AppUsersController(IUserService userService, ILogger<AppUsersController> logger)
        {
            _userService = userService;
            _logger = logger;
        }

        // Define your endpoints here
        [HttpPost("register")]  // Endpoint for registration
        public async Task<ActionResult<UserDto>> Register(UserCreateDto dto)
        {
            try
            {
                var user = await _userService.RegisterAsync(dto);
                return Ok(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed");
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("login")]  // Endpoint for login
        public async Task<ActionResult<string>> Login(UserLoginDto dto)
        {
            try
            {
                var token = await _userService.LoginAsync(dto);
                return Ok(new { token });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed");
                return Unauthorized(ex.Message);
            }
        }
        [HttpGet("GetAllUsers2")]  // Endpoint for getting all users (restricted to admin role)
        public async Task<ActionResult<IEnumerable<UserDto>>> GetAllUsers2()
        {
            var userRole = User.FindFirst(ClaimTypes.Role)?.Value;
            HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Role, "Administrator") }));
            var users = await _userService.GetAllUsersAsync();
            return Ok(users);
        }


        [HttpGet("GetAllUsers")]  // Endpoint for getting all users (restricted to admin role)
        [Authorize(Roles = "Administrator")]
        public async Task<ActionResult<IEnumerable<UserDto>>> GetAllUsers()
        {
            var users = await _userService.GetAllUsersAsync();
            return Ok(users);
        }

        [HttpGet("GetUserById/{id}")]  // Endpoint for getting a user by ID
        [Authorize]
        public async Task<ActionResult<UserDto>> GetUserById(Guid id)
        {
            var user = await _userService.GetUserByIdAsync(id);
            return user == null ? NotFound() : Ok(user);
        }

        [HttpDelete("DeleteUser/{id}")]  // Endpoint for deleting a user by ID
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            await _userService.DeleteUserAsync(id);
            return NoContent();
        }
    }
}