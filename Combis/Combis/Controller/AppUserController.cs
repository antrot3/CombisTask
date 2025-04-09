using CommonLayer.DtoModells;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ServiceLayer.Interface;
using System.Security.Claims;

namespace Combis.Controller
{
    [ApiController]
    [Route("api/[controller]")]
    public class AppUsersController : ControllerBase
    {
        private readonly IAppUserService _appUserService;
        private readonly ILogger<AppUsersController> _logger;

        public AppUsersController(IAppUserService appUserService, ILogger<AppUsersController> logger)
        {
            _appUserService = appUserService;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(UserCreateDto dto)
        {
            try
            {
                var user = await _appUserService.RegisterAsync(dto);
                return Ok(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed");
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserLoginDto dto)
        {
            try
            {
                var token = await _appUserService.LoginAsync(dto);
                return Ok(new { token });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed");
                return Unauthorized(ex.Message);
            }
        }

        [HttpPost("UpdateUserByEmail")]
        [Authorize(Roles = "Administrator")]
        public async Task<ActionResult<string>> UpdateUserByEmail(UserDto dto)
        {
            try
            {
                var user = await _appUserService.UpdateUser(dto);
                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Update Failed");
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("UpdateUserById")]
        [Authorize(Roles = "Administrator")]
        public async Task<ActionResult<string>> UpdateUserById(UserDto dto)
        {
            try
            {
                var user = await _appUserService.UpdateUserById(dto);
                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Update Failed");
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("GetAllUsers")]
        [Authorize(Roles = "Administrator")]
        public async Task<ActionResult<IEnumerable<UserDto>>> GetAllUsers()
        {
            var users = await _appUserService.GetAllUsersAsync();
            return Ok(users);
        }

        [HttpGet("GetUserById/{id}")]
        [Authorize]
        public async Task<ActionResult<UserDto>> GetUserById(Guid id)
        {
            var user = await _appUserService.GetUserByIdAsync(id);
            return user == null ? NotFound() : Ok(user);
        }



        [HttpDelete("DeleteUser/{id}")]
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            await _appUserService.DeleteUserByIdAsync(id);
            return NoContent();
        }
    }
}