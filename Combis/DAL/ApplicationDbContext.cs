using DAL.Models;
using Microsoft.EntityFrameworkCore;

namespace DAL
{

    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
        public DbSet<AppUser> AppUsers { get; set; }

    }
}
