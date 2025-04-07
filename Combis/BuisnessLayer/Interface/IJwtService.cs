using DAL.Models;

namespace BuisnessLayer.Interface
{
    public interface IJwtService
    {
        string GenerateToken(AppUser user);
    }
}
