using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using Microsoft.AspNetCore.Mvc;
using ServiceLayer.Interface;

namespace ServiceLayer.Service
{
    public class AppUserService : IAppUserService
    {
        private readonly IUserService _userService;

        public AppUserService(IUserService userService)
        {
            _userService = userService;
        }

        public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
        {
            return await _userService.GetAllUsersAsync();
        }

        public async Task<ActionResult<UserDto>> RegisterAsync(UserCreateDto userDto)
        {
            return await _userService.RegisterAsync(userDto);
        }

        public async Task<ActionResult<string>> LoginAsync(UserLoginDto loginDto)
        {
            return await _userService.LoginAsync(loginDto);
        }

        public async Task<ActionResult<UserDto>> GetUserByIdAsync(Guid id)
        {
            return await _userService.GetUserByIdAsync(id);
        }

        public async Task<bool> DeleteUserByIdAsync(Guid id)
        {
            return await _userService.DeleteUserAsync(id);
        }

        public async Task<bool> UpdateUser(UserDto userDto)
        {
            return await _userService.UpdateUser(userDto);;
        }
    }
}