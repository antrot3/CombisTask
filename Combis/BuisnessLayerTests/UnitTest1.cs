using BuisnessLayer.Interface;
using CommonLayer.DtoModells;
using DAL.Interface;
using DAL.Models;
using Moq;

namespace BuisnessLayer.Tests
{
    [TestClass]
    public class UserServiceTests
    {
        private Mock<IUserRepository> _mockRepo;
        private Mock<IJwtService> _mockJwtService;
        private IUserService _userService;

        [TestInitialize]
        public void SetUp()
        {
            // Initialize the mocks
            _mockRepo = new Mock<IUserRepository>();
            _mockJwtService = new Mock<IJwtService>();

            // Initialize the UserService with mocked dependencies
            _userService = new UserService(_mockRepo.Object, _mockJwtService.Object);
        }

        [TestMethod]
        public async Task RegisterAsync_UserAlreadyExists_ThrowsException()
        {
            // Arrange
            var dto = new UserCreateDto
            {
                FullName = "John Doe",
                Email = "john.doe@example.com",
                Password = "Password123",
                IsAdministrator = false
            };

            _mockRepo.Setup(repo => repo.GetByEmailAsync(dto.Email)).ReturnsAsync(new AppUser());

            // Act & Assert
            await Assert.ThrowsExceptionAsync<Exception>(async () => await _userService.RegisterAsync(dto));
        }

        [TestMethod]
        public async Task RegisterAsync_UserDoesNotExist_ReturnsUserDto()
        {
            // Arrange
            var dto = new UserCreateDto
            {
                FullName = "John Doe",
                Email = "john.doe@example.com",
                Password = "Password123",
                IsAdministrator = false
            };

            var appUser = new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                Role = "User"
            };

            _mockRepo.Setup(repo => repo.GetByEmailAsync(dto.Email)).ReturnsAsync((AppUser)null);
            _mockRepo.Setup(repo => repo.AddAsync(It.IsAny<AppUser>())).ReturnsAsync(appUser);

            // Act
            var result = await _userService.RegisterAsync(dto);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(dto.FullName, result.FullName);
            Assert.AreEqual(dto.Email, result.Email);
            Assert.AreEqual("User", result.Role);
        }

        [TestMethod]
        public async Task LoginAsync_InvalidCredentials_ThrowsException()
        {
            // Arrange
            var dto = new UserLoginDto
            {
                Email = "john.doe@example.com",
                Password = "WrongPassword"
            };

            _mockRepo.Setup(repo => repo.GetByEmailAsync(dto.Email)).ReturnsAsync((AppUser)null);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<Exception>(async () => await _userService.LoginAsync(dto));
        }

        [TestMethod]
        public async Task LoginAsync_ValidCredentials_ReturnsToken()
        {
            // Arrange
            var dto = new UserLoginDto
            {
                Email = "john.doe@example.com",
                Password = "Password123"
            };

            var appUser = new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = "John Doe",
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                Role = "User"
            };

            _mockRepo.Setup(repo => repo.GetByEmailAsync(dto.Email)).ReturnsAsync(appUser);
            _mockJwtService.Setup(jwt => jwt.GenerateToken(appUser)).Returns("generated-jwt-token");

            // Act
            var result = await _userService.LoginAsync(dto);

            // Assert
            Assert.AreEqual("generated-jwt-token", result);
        }

        // Test for RegisterAsync with a null email
        [TestMethod]
        public async Task RegisterAsync_NullEmail_ThrowsException()
        {
            // Arrange
            var dto = new UserCreateDto
            {
                FullName = "John Doe",
                Email = null, // Null email
                Password = "Password123",
                IsAdministrator = false
            };

            // Act & Assert
            await Assert.ThrowsExceptionAsync<ArgumentNullException>(async () => await _userService.RegisterAsync(dto));
        }

        // Test for RegisterAsync with a blank password
        [TestMethod]
        public async Task RegisterAsync_BlankPassword_ThrowsException()
        {
            // Arrange
            var dto = new UserCreateDto
            {
                FullName = "John Doe",
                Email = "john.doe@example.com",
                Password = "", // Blank password
                IsAdministrator = false
            };

            // Act & Assert
            await Assert.ThrowsExceptionAsync<ArgumentException>(async () => await _userService.RegisterAsync(dto));
        }

        // Test for RegisterAsync when IsAdministrator is not set
        [TestMethod]
        public async Task RegisterAsync_NoRoleSet_SetsUserRoleAsUser()
        {
            // Arrange
            var dto = new UserCreateDto
            {
                FullName = "John Doe",
                Email = "john.doe@example.com",
                Password = "Password123",
                IsAdministrator = false // Not an administrator
            };

            var appUser = new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                Role = "User" // Default role should be User
            };

            _mockRepo.Setup(repo => repo.GetByEmailAsync(dto.Email)).ReturnsAsync((AppUser)null);
            _mockRepo.Setup(repo => repo.AddAsync(It.IsAny<AppUser>())).ReturnsAsync(appUser);

            // Act
            var result = await _userService.RegisterAsync(dto);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("User", result.Role); // Role should be User
        }

        // Test for LoginAsync with incorrect password
        [TestMethod]
        public async Task LoginAsync_IncorrectPassword_ThrowsException()
        {
            // Arrange
            var dto = new UserLoginDto
            {
                Email = "john.doe@example.com",
                Password = "WrongPassword" // Incorrect password
            };

            var appUser = new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = "John Doe",
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("CorrectPassword") // Correct password hash
            };

            _mockRepo.Setup(repo => repo.GetByEmailAsync(dto.Email)).ReturnsAsync(appUser);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<Exception>(async () => await _userService.LoginAsync(dto));
        }

        // Test for LoginAsync when the email is not found
        [TestMethod]
        public async Task LoginAsync_EmailNotFound_ThrowsException()
        {
            // Arrange
            var dto = new UserLoginDto
            {
                Email = "nonexistent@example.com",
                Password = "Password123"
            };

            // Mock the repository to return null for a non-existent email
            _mockRepo.Setup(repo => repo.GetByEmailAsync(dto.Email)).ReturnsAsync((AppUser)null);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<Exception>(async () => await _userService.LoginAsync(dto));
        }

        // Test for GetUserByIdAsync with valid user id
        [TestMethod]
        public async Task GetUserByIdAsync_ValidUserId_ReturnsUserDto()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var appUser = new AppUser { Id = userId, FullName = "John Doe", Email = "john.doe@example.com", Role = "User" };

            _mockRepo.Setup(repo => repo.GetByIdAsync(userId)).ReturnsAsync(appUser);

            // Act
            var result = await _userService.GetUserByIdAsync(userId);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(userId, result.Id);
            Assert.AreEqual("John Doe", result.FullName);
            Assert.AreEqual("john.doe@example.com", result.Email);
        }

        // Test for DeleteUserAsync when user does not exist
        [TestMethod]
        public async Task DeleteUserAsync_UserDoesNotExist_ReturnsFalse()
        {
            // Arrange
            var userId = Guid.NewGuid();

            _mockRepo.Setup(repo => repo.GetByIdAsync(userId)).ReturnsAsync((AppUser)null); // User does not exist

            // Act
            var result = await _userService.DeleteUserAsync(userId);

            // Assert
            Assert.IsFalse(result); // Should return false as the user doesn't exist
        }

        // Test for GetAllUsersAsync when there are no users
        [TestMethod]
        public async Task GetAllUsersAsync_NoUsers_ReturnsEmptyList()
        {
            // Arrange
            _mockRepo.Setup(repo => repo.GetAllAsync()).ReturnsAsync(new List<AppUser>()); // No users in the repo

            // Act
            var result = await _userService.GetAllUsersAsync();

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(0, result.Count()); // Should return an empty list
        }

        // Test for DeleteUserAsync when user exists and is deleted
        [TestMethod]
        public async Task DeleteUserAsync_UserExists_DeletesUserAndReturnsTrue()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var appUser = new AppUser { Id = userId, FullName = "John Doe", Email = "john.doe@example.com", Role = "User" };

            _mockRepo.Setup(repo => repo.GetByIdAsync(userId)).ReturnsAsync(appUser);
            _mockRepo.Setup(repo => repo.DeleteAsync(appUser)).Returns(Task.CompletedTask); // Mock delete

            // Act
            var result = await _userService.DeleteUserAsync(userId);

            // Assert
            Assert.IsTrue(result); // Should return true as the user was deleted successfully
        }

        // Test for RegisterAsync when an exception is thrown from AddAsync
        [TestMethod]
        public async Task RegisterAsync_AddUserThrowsException_ThrowsException()
        {
            // Arrange
            var dto = new UserCreateDto
            {
                FullName = "John Doe",
                Email = "john.doe@example.com",
                Password = "Password123",
                IsAdministrator = false
            };

            var appUser = new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                Role = "User"
            };

            _mockRepo.Setup(repo => repo.GetByEmailAsync(dto.Email)).ReturnsAsync((AppUser)null);
            _mockRepo.Setup(repo => repo.AddAsync(It.IsAny<AppUser>())).ThrowsAsync(new Exception("Database error"));

            // Act & Assert
            await Assert.ThrowsExceptionAsync<Exception>(async () => await _userService.RegisterAsync(dto));
        }

        [TestMethod]
        public async Task GetAllUsersAsync_ReturnsUserDtos()
        {
            // Arrange
            var appUsers = new List<AppUser>
            {
                new AppUser { Id = Guid.NewGuid(), FullName = "John Doe", Email = "john.doe@example.com", Role = "User" },
                new AppUser { Id = Guid.NewGuid(), FullName = "Jane Smith", Email = "jane.smith@example.com", Role = "Administrator" }
            };

            _mockRepo.Setup(repo => repo.GetAllAsync()).ReturnsAsync(appUsers);

            // Act
            var result = await _userService.GetAllUsersAsync();

            // Assert
            Assert.AreEqual(2, result.Count());
            Assert.IsTrue(result.Any(u => u.Email == "john.doe@example.com"));
            Assert.IsTrue(result.Any(u => u.Email == "jane.smith@example.com"));
        }

        [TestMethod]
        public async Task GetUserByIdAsync_UserExists_ReturnsUserDto()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var appUser = new AppUser { Id = userId, FullName = "John Doe", Email = "john.doe@example.com", Role = "User" };

            _mockRepo.Setup(repo => repo.GetByIdAsync(userId)).ReturnsAsync(appUser);

            // Act
            var result = await _userService.GetUserByIdAsync(userId);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(userId, result.Id);
            Assert.AreEqual("John Doe", result.FullName);
        }

        [TestMethod]
        public async Task GetUserByIdAsync_UserDoesNotExist_ReturnsNull()
        {
            // Arrange
            var userId = Guid.NewGuid();

            _mockRepo.Setup(repo => repo.GetByIdAsync(userId)).ReturnsAsync((AppUser)null);

            // Act
            var result = await _userService.GetUserByIdAsync(userId);

            // Assert
            Assert.IsNull(result);
        }

        [TestMethod]
        public async Task DeleteUserAsync_UserExists_ReturnsTrue()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var appUser = new AppUser { Id = userId, FullName = "John Doe", Email = "john.doe@example.com", Role = "User" };

            _mockRepo.Setup(repo => repo.GetByIdAsync(userId)).ReturnsAsync(appUser);
            _mockRepo.Setup(repo => repo.DeleteAsync(appUser)).Returns(Task.CompletedTask);

            // Act
            var result = await _userService.DeleteUserAsync(userId);

            // Assert
            Assert.IsTrue(result);
        }
    }
}
