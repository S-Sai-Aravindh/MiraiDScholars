namespace Institute_Management.DTOs
{
    public class BatchDTO
    {
        public int? BatchId { get; set; }
        public string? BatchName { get; set; }
        public string? BatchTiming { get; set; }
        public string? BatchType { get; set; }

        public int? CourseId { get; set; }

        public CourseDTO? Course { get; set; }
    }
}
