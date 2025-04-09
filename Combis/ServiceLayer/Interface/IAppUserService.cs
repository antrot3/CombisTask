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
        Task<bool> UpdateUser(UserDto userDto);

        Task<bool> UpdateUserById(UserDto userDto);
        Task<ActionResult<UserAuthResult>> LoginUserToAppAsync(UserLoginDto loginDto);
    }
}
