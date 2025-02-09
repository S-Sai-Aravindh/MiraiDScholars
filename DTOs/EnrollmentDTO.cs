namespace Institute_Management.DTOs
{
    public class EnrollmentDTO
    {
        public int? StudentId { get; set; }
        public int? CourseId { get; set; }

        public CourseDTO? Course { get; set; }  // To include course details
    }
}
