using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using DAL.Interface;
using DAL.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

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
            if (string.IsNullOrWhiteSpace(dto.FullName))
            {
                throw new Exception("Full Name is required.");
            }

            if (string.IsNullOrWhiteSpace(dto.Email) || !IsValidEmail(dto.Email))
            {
                throw new Exception("Invalid Email address.");
            }

            var existing = await _repo.GetByEmailAsync(dto.Email);
            if (existing != null) throw new Exception("User already exists");

            var passwordErrors = ValidatePassword(dto.Password);
            if (passwordErrors.Any())
                throw new Exception("Password validation failed: " + string.Join("; ", passwordErrors));

            var hash = BCrypt.Net.BCrypt.HashPassword(dto.Password);

            var user = new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = hash,
                Role = dto.IsAdministrator == true ? "Administrator" : "Klijent"
            };

            var created = await _repo.AddAsync(user);
            return new UserDto{Id = created.Id, FullName = created.FullName, Email = created.Email, Role = created.Role};
        }

        public async Task<string> LoginAsync(UserLoginDto dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Email) || !IsValidEmail(dto.Email))
            {
                throw new Exception("Invalid Email address.");
            }
            var user = await _repo.GetByEmailAsync(dto.Email);
            var passwordErrors = ValidatePassword(dto.Password);

            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                throw new Exception("Invalid credentials");

            return _jwtService.GenerateToken(user);
        }

        public async Task<UserAuthResult> LoginUserToAppAsync(UserLoginDto dto)
        {
            var token = await LoginAsync(dto);
            if (string.IsNullOrWhiteSpace(token))
                throw new Exception("Invalid credentials");

            var user = await _repo.GetByEmailAsync(dto.Email) ?? throw new Exception("User not found");

            var claims = new JwtSecurityTokenHandler()
                            .ReadJwtToken(token)
                            .Claims;

            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));

            return new UserAuthResult
            {
                Principal = principal,
                User = new UserDto
                {
                    Id = user.Id,
                    FullName = user.FullName,
                    Email = user.Email,
                    Role = user.Role
                }
            };
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
            if (string.IsNullOrWhiteSpace(userDto.Email) || !IsValidEmail(userDto.Email))
            {
                throw new Exception("Invalid Email address.");
            }

            var user = await _repo.GetByEmailAsync(userDto.Email);
            if (user == null)
            {
                throw new Exception("User does not exist");
            }
            
            if (userDto.Role != "Administrator" && userDto.Role != "Klijent")
            {
                throw new Exception("Role must be either 'Administrator' or 'Klijent'.");
            }

            user.FullName = userDto.FullName;
            user.Email = userDto.Email;
            user.Role = userDto.Role;

            await _repo.UpdateAsync(user);
            return true; 
        }

        public async Task<bool> UpdateUserById(UserDto userDto)
        {
            if (string.IsNullOrWhiteSpace(userDto.Email) || !IsValidEmail(userDto.Email))
            {
                throw new Exception("Invalid Email address.");
            }
            if (userDto.Role != "Administrator" && userDto.Role != "Klijent")
            {
                throw new Exception("Role must be either 'Administrator' or 'Klijent'.");
            }

            var user = await _repo.GetByIdAsync(userDto.Id);
            if (user == null)
            {
                throw new Exception("User does not exist");
            }

            if (userDto.Role != "Administrator" && userDto.Role != "Klijent")
            {
                throw new Exception("Role must be either 'Administrator' or 'Klijent'.");
            }
           
            user.FullName = userDto.FullName;
            user.Email = userDto.Email;
            user.Role = userDto.Role;

            await _repo.UpdateAsync(user);
            return true; 
        }

        private List<string> ValidatePassword(string password)
        {
            var errors = new List<string>();

            if (password.Length < 8)
                errors.Add("Password must be at least 8 characters long.");

            if (!password.Any(char.IsUpper))
                errors.Add("Password must contain at least one uppercase letter.");

            if (!password.Any(char.IsLower))
                errors.Add("Password must contain at least one lowercase letter.");

            if (!password.Any(char.IsDigit))
                errors.Add("Password must contain at least one digit.");

            if (password.Distinct().Count() < 1)
                errors.Add("Password must contain at least one unique character.");

            return errors;
        }

        private bool IsValidEmail(string email)
        {
            var parts = email.Split('@');
            if (parts.Length != 2) return false;

            var local = parts[0];
            var domain = parts[1];
            if (string.IsNullOrWhiteSpace(local) || string.IsNullOrWhiteSpace(domain)) return false;

            return domain.Contains(".");
        }

    }
}
