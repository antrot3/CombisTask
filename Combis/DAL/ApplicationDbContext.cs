using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using DAL.Models;
using Microsoft.AspNetCore.Identity;

namespace DAL
{
    public class ApplicationDbContext : IdentityDbContext<AppUser, IdentityRole<Guid>, Guid> // Specify IdentityRole and Guid for key
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
        public DbSet<AppUser> AppUsers { get; set; } // Optionally, you can keep this DbSet if needed
    }
}