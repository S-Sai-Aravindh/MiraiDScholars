namespace Institute_Management.DTOs
{
    public class StudentDTO
    {
        public int? StudentId { get; set; }
        public int? UserId { get; set; }
        public int? BatchId { get; set; }

        public UserDTO? User { get; set; }  // To include User details
        public BatchDTO? Batch { get; set; }  // To include Batch details

        public List<EnrollmentDTO>? Enrollments { get; set; }
    }
}
