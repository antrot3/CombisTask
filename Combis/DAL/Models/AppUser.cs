using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace DAL.Models
{
    public class AppUser : IdentityUser<Guid> // Inherit from IdentityUser and use Guid as the key
    {
        [Required]
        [MaxLength(100)]
        public string FullName { get; set; }

        [Required]
        public string Role { get; set; } = "Korisnik"; // or "Administrator"
    }
}