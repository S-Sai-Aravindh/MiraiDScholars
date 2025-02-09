namespace Institute_Management.DTOs
{
    public class CourseDTO
    {
        public int? CourseId { get; set; }
        public string? CourseName { get; set; }
        public string? Description { get; set; }

        public TeacherDTO? Teacher { get; set; }  // To include teacher details
    }
}
