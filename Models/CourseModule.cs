using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Institute_Management.Models
{
    public class CourseModule
    {
        public class Course
        {
            [Key]
            public int? CourseId { get; set; }

            public string CourseName { get; set; } = string.Empty;

            public string Description { get; set; } = string.Empty;

            public int? TeacherId { get; set; }

            [ForeignKey("TeacherId")]
            public virtual TeacherModule.Teacher? Teacher { get; set; }

            public virtual List<StudentCourseModule.StudentCourse> Enrollments { get; set; } = new List<StudentCourseModule.StudentCourse>();
        }

    }
}
