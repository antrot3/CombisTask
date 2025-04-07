using DAL.Interface;
using DAL.Models;
using Microsoft.EntityFrameworkCore;

namespace DAL
{
    public class UserRepository : IUserRepository
    {
        private readonly ApplicationDbContext _context;
        public UserRepository(ApplicationDbContext context) => _context = context;

        public async Task<AppUser> GetByEmailAsync(string email) =>
            await _context.AppUsers.FirstOrDefaultAsync(u => u.Email == email);

        public async Task<AppUser> GetByIdAsync(Guid id) =>
            await _context.AppUsers.FindAsync(id);

        public async Task<IEnumerable<AppUser>> GetAllAsync() =>
            await _context.AppUsers.ToListAsync();

        public async Task<AppUser> AddAsync(AppUser user)
        {
            _context.AppUsers.Add(user);
            await _context.SaveChangesAsync();
            return user;
        }

        public async Task UpdateAsync(AppUser user)
        {
            _context.AppUsers.Update(user);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(AppUser user)
        {
            _context.AppUsers.Remove(user);
            await _context.SaveChangesAsync();
        }
    }
}
