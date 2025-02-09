namespace Institute_Management.DTOs
{
    public class AdminDTO
    {
        public int? AdminId { get; set; }
        public int? UserId { get; set; }

        public UserDTO? User { get; set; }  // To include User details
    }
}
