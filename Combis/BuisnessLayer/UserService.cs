using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using DAL.Interface;

namespace BuisnessLayer
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _repo;

        public UserService(IUserRepository repo)
        {
            _repo = repo;
        }

        public async Task<UserDto> RegisterAsync(UserCreateDto dto)
        {

            throw new NotImplementedException();
        }

        public async Task<string> LoginAsync(UserLoginDto dto)
        {
            throw new NotImplementedException();
        }

        public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
        {
            throw new NotImplementedException();
        }

        public async Task<UserDto> GetUserByIdAsync(Guid id)
        {
            throw new NotImplementedException();
        }

        public async Task<bool> DeleteUserAsync(Guid id)
        {

            throw new NotImplementedException();
        }
    }
}
