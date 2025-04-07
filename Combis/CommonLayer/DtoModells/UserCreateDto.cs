namespace CommonLayer.DtoModells
{
    public class UserCreateDto
    {
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public bool IsAdministrator { get; set; }

    }
}
