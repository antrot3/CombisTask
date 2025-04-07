using CommonLayer.DtoModells;
using Microsoft.AspNetCore.Mvc;

namespace ServiceLayer.Interface
{
    public interface IAppUserService
    {
        Task<IEnumerable<UserDto>> GetAllUsersAsync();
        Task<ActionResult<UserDto>> RegisterAsync(UserCreateDto userDto);
        Task<ActionResult<string>> LoginAsync(UserLoginDto loginDto);
        Task<ActionResult<UserDto>> GetUserByIdAsync(Guid id);
        Task<bool> DeleteUserByIdAsync(Guid id);
    }
}
