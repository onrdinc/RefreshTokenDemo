using Microsoft.AspNetCore.Identity;

namespace DemoRefreshToken.Models.Domain
{
    public class ApplicationUser : IdentityUser
    {
        public string? Name { get; set; }
    }
}
