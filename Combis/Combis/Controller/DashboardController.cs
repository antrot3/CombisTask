using CommonLayer.DtoModells;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ServiceLayer.Interface;

namespace CombisMVC.Controllers
{
    public class DashboardController : Controller
    {
        private readonly IAppUserService _appUserService;

        public DashboardController(IAppUserService appUserService)
        {
            _appUserService = appUserService;
        }

        [HttpGet("Index/{id}")]
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> Index(Guid id)
        {
            AdminBoardDto dto = new AdminBoardDto();
            var users = await _appUserService.GetAllUsersAsync();
            dto.Users = users;
            dto.CurrentUserGuid = id;
            return View(dto);
        }

        [HttpGet("Klijent/{id}")]
        [Authorize(Roles = "Administrator, Klijent")]
        public async Task<IActionResult> Klijent(Guid id)
        {
            var user = await _appUserService.GetUserByIdAsync(id);
            return View(user.Value);
        }


        [HttpPost]
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> Delete(Guid id)
        {
            await _appUserService.DeleteUserByIdAsync(id);
            return RedirectToAction("Index");
        }


        [HttpPost]
        [Authorize(Roles = "Administrator, Klijent")]
        public async Task<IActionResult> UpdateUser([FromBody] UserDto dto)
        {
            await _appUserService.UpdateUserById(dto);
            return NoContent();
        }
    }
}