namespace Institute_Management.DTOs
{
    public class TeacherDTO
    {
        public int? TeacherId { get; set; }
        public int? UserId { get; set; }
        public string? SubjectSpecialization { get; set; }

        public UserDTO? User { get; set; }  // To include User details
        public List<CourseDTO>? Courses { get; set; }
    }
}
