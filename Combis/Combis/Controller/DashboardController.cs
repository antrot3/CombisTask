using CommonLayer.DtoModells;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ServiceLayer.Interface;

namespace CombisMVC.Controllers
{
    [Authorize(Roles = "Administrator")]
    public class DashboardController : Controller
    {
        private readonly IAppUserService _appUserService;

        public DashboardController(IAppUserService appUserService)
        {
            _appUserService = appUserService;
        }

        public async Task<IActionResult> Index()
        {
            var users = await _appUserService.GetAllUsersAsync();
            return View(users);
        }

        [HttpPost]
        public async Task<IActionResult> Delete(Guid id)
        {
            await _appUserService.DeleteUserByIdAsync(id);
            return RedirectToAction("Index");
        }


        [HttpPost]
        public async Task<IActionResult> UpdateUser([FromBody] UserDto dto)
        {
            await _appUserService.UpdateUser(dto);
            return NoContent();
        }
    }
}