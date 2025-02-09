using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Institute_Management.Models
{
    public class AdminModule
    {
        public class Admin
        {
            [Key]
            public int? AdminId { get; set; }

            public int? UserId { get; set; }

            [ForeignKey("UserId")]
            public virtual UserModule.User? User { get; set; }  // Use `virtual` for Lazy Loading
        }

    }
}
