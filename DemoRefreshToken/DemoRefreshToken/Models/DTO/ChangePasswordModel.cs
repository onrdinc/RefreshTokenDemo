using System.ComponentModel.DataAnnotations;

namespace DemoRefreshToken.Models.DTO
{
    public class ChangePasswordModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string CurrentPassword { get; set; }
        [Required]
        public string NewPassword { get; set; }
        [Required]
        [Compare("New Password")]
        public string ConfirmPassword { get; set; }
    }
}
