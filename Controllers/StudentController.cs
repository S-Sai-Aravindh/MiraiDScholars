using Institute_Management.DTOs;
using Institute_Management.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading.Tasks;

namespace Institute_Management.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StudentController : ControllerBase
    {
        private readonly InstituteContext _context;

        public StudentController(InstituteContext context)
        {
            _context = context;
        }
        //// http: //localhost:5109/api/student/students

        [HttpGet("students")]
        public async Task<ActionResult<IEnumerable<StudentDTO>>> GetAllStudents()
        {
            var students = await _context.Students
                .Include(s => s.User)
                .Include(s => s.Batch)
                .Include(s => s.Enrollments)
                .ThenInclude(e => e.Course)
                .Select(s => new StudentDTO
                {
                    StudentId = (int)s.StudentId,
                    UserId = (int)s.UserId,
                    BatchId = s.BatchId,
                    User = new UserDTO
                    {
                        UserId = (int)s.User.UserId,
                        Name = s.User.Name,
                        Email = s.User.Email,
                        Role = s.User.Role,
                        ContactDetails = s.User.ContactDetails
                    },
                    Batch = s.Batch != null ? new BatchDTO
                    {
                        BatchId = (int)s.Batch.BatchId,
                        BatchName = s.Batch.BatchName,
                        BatchTiming = s.Batch.BatchTiming,
                        BatchType = s.Batch.BatchType
                    } : null,
                    Enrollments = s.Enrollments.Select(e => new EnrollmentDTO
                    {
                        StudentId = (int)e.StudentId,
                        CourseId = (int)e.CourseId,
                        Course = new CourseDTO
                        {
                            CourseId = (int)e.Course.CourseId,
                            CourseName = e.Course.CourseName,
                            Description = e.Course.Description
                        }
                    }).ToList()
                })
                .ToListAsync();

            return Ok(students);
        }




        // 1. Get Student Profile
        [HttpGet("{id}")]
        public async Task<IActionResult> GetStudentProfile(int id)
        {
            var student = await _context.Students
                .Include(s => s.User)
                .Include(s => s.Enrollments)
                .ThenInclude(e => e.Course)
                .FirstOrDefaultAsync(s => s.StudentId == id);

            if (student == null) return NotFound();

            var studentDto = new StudentDTO
            {
                StudentId = (int)student.StudentId,
                UserId = (int)student.UserId,
                BatchId = student.BatchId,
                User = new UserDTO
                {
                    UserId = (int)student.User.UserId,
                    Name = student.User.Name,
                    Email = student.User.Email,
                    Role = student.User.Role,
                    ContactDetails = student.User.ContactDetails
                },
                Batch = student.Batch != null ? new BatchDTO
                {
                    BatchId = (int)student.Batch.BatchId,
                    BatchName = student.Batch.BatchName,
                    BatchTiming = student.Batch.BatchTiming,
                    BatchType = student.Batch.BatchType
                } : null,
                Enrollments = student.Enrollments.Select(e => new EnrollmentDTO
                {
                    StudentId = (int)e.StudentId,
                    CourseId = (int)e.CourseId,
                    Course = new CourseDTO
                    {
                        CourseId = (int)e.Course.CourseId,
                        CourseName = e.Course.CourseName,
                        Description = e.Course.Description
                    }
                }).ToList()
            };

            return Ok(studentDto);
        }

        // 2. Update Student Profile
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateStudentProfile(int id, [FromBody] StudentDTO updatedStudentDto)
        {
            var student = await _context.Students
                .Include(s => s.User)  // Ensure User is included
                .FirstOrDefaultAsync(s => s.StudentId == id);

            if (student == null) return NotFound();

            // Update User details
            student.User.Name = updatedStudentDto.User.Name;
            student.User.Email = updatedStudentDto.User.Email;
            student.User.ContactDetails = updatedStudentDto.User.ContactDetails;
            student.User.Role = updatedStudentDto.User.Role;

            // Update Batch details if needed
            student.BatchId = updatedStudentDto.BatchId;

            // Update Enrollments if needed
            // You can also update enrollments, but it seems like only Batch and User need to be updated here.

            await _context.SaveChangesAsync();

            // Return the updated student profile
            var updatedStudent = await _context.Students
                .Include(s => s.User)
                .Include(s => s.Enrollments)
                .ThenInclude(e => e.Course)
                .FirstOrDefaultAsync(s => s.StudentId == id);

            var studentDto = new StudentDTO
            {
                StudentId = (int)updatedStudent.StudentId,
                UserId = (int)updatedStudent.UserId,
                BatchId = updatedStudent.BatchId,
                User = new UserDTO
                {
                    UserId = (int)updatedStudent.User.UserId,
                    Name = updatedStudent.User.Name,
                    Email = updatedStudent.User.Email,
                    Role = updatedStudent.User.Role,
                    ContactDetails = updatedStudent.User.ContactDetails
                },
                Batch = updatedStudent.Batch != null ? new BatchDTO
                {
                    BatchId = (int)updatedStudent.Batch.BatchId,
                    BatchName = updatedStudent.Batch.BatchName,
                    BatchTiming = updatedStudent.Batch.BatchTiming,
                    BatchType = updatedStudent.Batch.BatchType
                } : null,
                Enrollments = updatedStudent.Enrollments.Select(e => new EnrollmentDTO
                {
                    StudentId = (int)e.StudentId,
                    CourseId = (int)e.CourseId,
                    Course = new CourseDTO
                    {
                        CourseId = (int)e.Course.CourseId,
                        CourseName = e.Course.CourseName,
                        Description = e.Course.Description
                    }
                }).ToList()
            };

            return Ok(studentDto);
        }



        // 3. Get Available Courses
        [HttpGet("courses")]
        public async Task<IActionResult> GetCourses()
        {
            var courses = await _context.Courses
                .Select(c => new CourseDTO
                {
                    CourseId = (int)c.CourseId,
                    CourseName = c.CourseName,
                    Description = c.Description
                })
                .ToListAsync();

            return Ok(courses);
        }

        // 4. Enroll in a Course
        [HttpPost("enroll")]
        public async Task<IActionResult> EnrollInCourse([FromBody] EnrollmentDTO enrollmentDto)
        {
            var enrollment = new StudentCourseModule.StudentCourse
            {
                StudentId = enrollmentDto.StudentId,
                CourseId = enrollmentDto.CourseId
            };

            _context.StudentCourses.Add(enrollment);
            await _context.SaveChangesAsync();
            return Ok(new { message = "Enrollment successful" });
        }

        // 5. Get Student's Assigned Batches
        [HttpGet("{studentId}/batches")]
        public async Task<IActionResult> GetStudentBatches(int studentId)
        {
            var batches = await _context.Batches
                .Where(b => _context.StudentCourses.Any(sc => sc.StudentId == studentId && sc.CourseId == b.CourseId))
                .Select(b => new BatchDTO
                {
                    BatchId = (int)b.BatchId,
                    BatchName = b.BatchName,
                    BatchTiming = b.BatchTiming,
                    BatchType = b.BatchType
                })
                .ToListAsync();

            return Ok(batches);
        }
    }
}
