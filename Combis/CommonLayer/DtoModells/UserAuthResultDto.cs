using System.Security.Claims;

namespace CommonLayer.DtoModells
{
    public class UserAuthResult
    {
        public ClaimsPrincipal Principal { get; set; }
        public UserDto User { get; set; }
    }
}
