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
        private Mock<IUserRepository> _repoMock;
        private Mock<IJwtService> _jwtServiceMock;
        private UserService _userService;

        [TestInitialize]
        public void TestInitialize()
        {
            _repoMock = new Mock<IUserRepository>();
            _jwtServiceMock = new Mock<IJwtService>();
            _userService = new UserService(_repoMock.Object, _jwtServiceMock.Object);
        }

        [TestMethod]
        [DataRow("invalidemail", "Test1234", "Invalid Email address.")]
        [DataRow("antrot3@gmail.com", "Test1234", "User already exists")]
        public async Task RegisterAsync_ShouldThrowException_ForVariousCases(string email, string password, string expectedErrorMessage)
        {
            // Arrange
            var userDto = new UserCreateDto
            {
                FullName = "Ante Rota",
                Email = email,
                Password = password
            };

            if (email == "antrot3@gmail.com" && password == "Test1234")
            {
                var existingUser = new AppUser
                {
                    Id = Guid.NewGuid(),
                    FullName = "Ante Rota",
                    Email = "antrot3@gmail.com",
                    PasswordHash = "hashedpassword",
                    Role = "Klijent"
                };
                _repoMock.Setup(repo => repo.GetByEmailAsync(It.IsAny<string>())).ReturnsAsync(existingUser);
            }
            else
            {
                _repoMock.Setup(repo => repo.GetByEmailAsync(It.IsAny<string>())).ReturnsAsync((AppUser)null);
            }

            var ex = await Assert.ThrowsExceptionAsync<Exception>(() => _userService.RegisterAsync(userDto));
            Assert.AreEqual(expectedErrorMessage, ex.Message);
        }

        [TestMethod]
        [DataRow("validemail@test.com", "Test1234", true)] 
        [DataRow("mail.com", "Test1234", false)] 
        [DataRow("validemail@test.com", "WrongPassword", false)]
        public async Task LoginAsync_ShouldReturnTokenOrThrowException(string email, string password, bool isValid)
        {
            // Arrange
            var userDto = new UserLoginDto
            {
                Email = email,
                Password = password
            };

            var existingUser = new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = "Ante Rota",
                Email = "validemail@test.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Test1234"),
                Role = "Klijent"
            };

            _repoMock.Setup(repo => repo.GetByEmailAsync(It.IsAny<string>())).ReturnsAsync(existingUser);
            _jwtServiceMock.Setup(jwt => jwt.GenerateToken(It.IsAny<AppUser>())).Returns("ValidJWTToken");

            // Act & Assert
            if (isValid)
            {
                var token = await _userService.LoginAsync(userDto);
                Assert.AreEqual("ValidJWTToken", token);
            }
            else
            {
                await Assert.ThrowsExceptionAsync<Exception>(() => _userService.LoginAsync(userDto), "Invalid credentials");
            }
        }

        [TestMethod]
        public async Task RegisterAsync_ValidUser_ShouldReturnUserDto()
        {
            // Arrange
            var userDto = new UserCreateDto
            {
                FullName = "Ante Rota",
                Email = "newuser@test.com",
                Password = "ValidPassword123",
                IsAdministrator = false
            };

            _repoMock.Setup(repo => repo.GetByEmailAsync(It.IsAny<string>())).ReturnsAsync((AppUser)null);
            _repoMock.Setup(repo => repo.AddAsync(It.IsAny<AppUser>())).ReturnsAsync(new AppUser
            {
                Id = Guid.NewGuid(),
                FullName = "Ante Rota",
                Email = "newuser@test.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("ValidPassword123"),
                Role = "Klijent"
            });

            // Act
            var result = await _userService.RegisterAsync(userDto);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("Ante Rota", result.FullName);
            Assert.AreEqual("newuser@test.com", result.Email);
            Assert.AreEqual("Klijent", result.Role);
        }

        [TestMethod]
        public async Task DeleteUserAsync_ShouldReturnTrue_WhenUserExists()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var existingUser = new AppUser
            {
                Id = userId,
                FullName = "Ante Rota",
                Email = "deleteduser@test.com",
                PasswordHash = "somepasswordhash",
                Role = "Klijent"
            };

            _repoMock.Setup(repo => repo.GetByIdAsync(It.IsAny<Guid>())).ReturnsAsync(existingUser);
            _repoMock.Setup(repo => repo.DeleteAsync(It.IsAny<AppUser>())).Returns(Task.CompletedTask);

            // Act
            var result = await _userService.DeleteUserAsync(userId);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public async Task DeleteUserAsync_ShouldReturnFalse_WhenUserDoesNotExist()
        {
            // Arrange
            var userId = Guid.NewGuid();
            _repoMock.Setup(repo => repo.GetByIdAsync(It.IsAny<Guid>())).ReturnsAsync((AppUser)null);

            // Act
            var result = await _userService.DeleteUserAsync(userId);

            // Assert
            Assert.IsFalse(result);
        }
    }
}
