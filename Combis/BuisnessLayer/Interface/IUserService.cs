using CommonLayer.DtoModells;
using System.Security.Claims;

namespace BuisnessLayer.Interface
{
    public interface IUserService
    {
        Task<UserDto> RegisterAsync(UserCreateDto dto);
        Task<string> LoginAsync(UserLoginDto dto);
        Task<IEnumerable<UserDto>> GetAllUsersAsync();
        Task<UserDto> GetUserByIdAsync(Guid id);
        Task<bool> DeleteUserAsync(Guid id);
        Task<bool> UpdateUser(UserDto userDto);
        Task<UserAuthResult> LoginUserToAppAsync(UserLoginDto dto);
    }
}
