using DAL.Models;

namespace DAL.Interface
{
    public interface IUserRepository
    {
        Task<AppUser> GetByEmailAsync(string email);
        Task<AppUser> GetByIdAsync(Guid id);
        Task<IEnumerable<AppUser>> GetAllAsync();
        Task<AppUser> AddAsync(AppUser user);
        Task UpdateAsync(AppUser user);
        Task DeleteAsync(AppUser user);
    }
}
