using System.ComponentModel.DataAnnotations.Schema;

namespace Institute_Management.Models
{
    public class StudentCourseModule
    {
        public class StudentCourse
        {
            public int? StudentId { get; set; }

            public int? CourseId { get; set; }

            [ForeignKey("StudentId")]
            public virtual StudentModule.Student? Student { get; set; }

            [ForeignKey("CourseId")]
            public virtual CourseModule.Course? Course { get; set; }
        }

    }
}
