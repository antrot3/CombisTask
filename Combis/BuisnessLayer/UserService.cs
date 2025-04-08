using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using DAL.Interface;
using DAL.Models;

namespace BuisnessLayer
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _repo;
        private readonly IJwtService _jwtService;

        public UserService(IUserRepository repo, IJwtService jwtService)
        {
            _repo = repo;
            _jwtService = jwtService;
        }

        public async Task<UserDto> RegisterAsync(UserCreateDto dto)
        {

            var existing = await _repo.GetByEmailAsync(dto.Email);
            if (existing != null) throw new Exception("User already exists");

            var hash = BCrypt.Net.BCrypt.HashPassword(dto.Password);

            var user = new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = hash,
            };
            if (dto.IsAdministrator == true)
                user.Role = "Administrator";
            else
                user.Role = "User";

            var created = await _repo.AddAsync(user);

            return new UserDto { Id = created.Id, FullName = created.FullName, Email = created.Email, Role = created.Role };
        }

        public async Task<string> LoginAsync(UserLoginDto dto)
        {
            var user = await _repo.GetByEmailAsync(dto.Email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                throw new Exception("Invalid credentials");

            return _jwtService.GenerateToken(user);
        }

        public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
        {
            return (await _repo.GetAllAsync()).Select(u => new UserDto
            {
                Id = u.Id,
                FullName = u.FullName,
                Email = u.Email,
                Role = u.Role
            });
        }

        public async Task<UserDto> GetUserByIdAsync(Guid id)
        {
            var user = await _repo.GetByIdAsync(id);
            if (user == null) return null;

            return new UserDto { Id = user.Id, FullName = user.FullName, Email = user.Email, Role = user.Role };
        }

        public async Task<bool> DeleteUserAsync(Guid id)
        {
            var user = await _repo.GetByIdAsync(id);
            if (user != null)
            {
                await _repo.DeleteAsync(user);
                return true;
            }
            return false;

        }

        public async Task<bool> UpdateUser(UserDto userDto)
        {
            var user = await _repo.GetByEmailAsync(userDto.Email);
            if (user == null)
            {
                return false;
            }
            user.FullName = userDto.FullName;
            user.Email = userDto.Email;
            user.Role = userDto.Role;
            await _repo.UpdateAsync(user);
            return false;
        }

    }
}
