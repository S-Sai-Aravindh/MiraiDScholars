using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using static Institute_Management.Models.CourseModule;

namespace Institute_Management.Models
{
    public class TeacherModule
    {
        public class Teacher
        {

            [Key]
            public int? TeacherId { get; set; }

            public int? UserId { get; set; }

            public string SubjectSpecialization { get; set; } = string.Empty;

            [ForeignKey("UserId")]
            public virtual UserModule.User? User { get; set; }

            public virtual ICollection<CourseModule.Course> Courses { get; set; } = new List<CourseModule.Course>();
        }

    }
}
