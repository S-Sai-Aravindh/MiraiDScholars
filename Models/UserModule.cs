using System.ComponentModel.DataAnnotations;

namespace Institute_Management.Models
{
    public class UserModule
    {
        public class User
        {
            [Key]
            public int? UserId { get; set; }

            [Required]
            public string Name { get; set; } = string.Empty;

            [Required]
            public string Email { get; set; } = string.Empty;

            [Required]
            public string Password { get; set; } = string.Empty;

            [Required]
            public string Role { get; set; } = string.Empty;

            public string ContactDetails { get; set; } = string.Empty;
        }

    }
}
