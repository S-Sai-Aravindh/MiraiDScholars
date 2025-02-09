
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using static Institute_Management.Models.CourseModule;

namespace Institute_Management.Models
{
    public class BatchModule
    {
        public class Batch
        {
            [Key]
            public int? BatchId { get; set; }

            public string BatchName { get; set; } = string.Empty;

            public string BatchTiming { get; set; } = string.Empty;

            public string BatchType { get; set; } = string.Empty;

            public int? CourseId { get; set; }

            [ForeignKey("CourseId")]
            public virtual CourseModule.Course? Course { get; set; }

            public virtual ICollection<CourseModule.Course> Courses { get; set; } = new List<CourseModule.Course>();
        }

    }
}
