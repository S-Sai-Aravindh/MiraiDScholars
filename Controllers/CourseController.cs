using Institute_Management.DTOs;
using Institute_Management.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using static Institute_Management.Models.CourseModule;

namespace Institute_Management.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CourseController : ControllerBase
    {
        private readonly InstituteContext _context;

        public CourseController(InstituteContext context)
        {
            _context = context;
        }

        // 1. Get All Courses with related teacher information
        [HttpGet]
        public async Task<IActionResult> GetAllCourses()
        {
            var courses = await _context.Courses
                .Include(c => c.Teacher)  // Ensuring Teacher is loaded as well
                .Select(c => new CourseDTO
                {
                    CourseId = (int)c.CourseId,
                    CourseName = c.CourseName,
                    Description = c.Description,
                    Teacher = new TeacherDTO
                    {
                        TeacherId = (int)c.Teacher.TeacherId,
                        UserId = (int)c.Teacher.UserId,
                        SubjectSpecialization = c.Teacher.SubjectSpecialization
                    }
                })
                .ToListAsync();

            return Ok(courses);
        }

        // 2. Get Course by ID with related teacher information
        [HttpGet("{id}")]
        public async Task<IActionResult> GetCourseById(int id)
        {
            var course = await _context.Courses
                .Include(c => c.Teacher)  // Include Teacher for detailed info
                .Where(c => c.CourseId == id)
                .Select(c => new CourseDTO
                {
                    CourseId = (int)c.CourseId,
                    CourseName = c.CourseName,
                    Description = c.Description,
                    Teacher = new TeacherDTO
                    {
                        TeacherId = (int)c.Teacher.TeacherId,
                        UserId = (int)c.Teacher.UserId,
                        SubjectSpecialization = c.Teacher.SubjectSpecialization
                    }
                })
                .FirstOrDefaultAsync();

            if (course == null) return NotFound();
            return Ok(course);
        }

        // 3. Create a New Course with Teacher information
        [HttpPost]
        public async Task<IActionResult> CreateCourse([FromBody] CourseDTO courseDto)
        {
            if (courseDto == null) return BadRequest();

            // Ensuring the teacher exists first
            var teacher = await _context.Teachers.FindAsync(courseDto.Teacher.TeacherId);
            if (teacher == null) return BadRequest("Teacher not found");

            var course = new Course
            {
                CourseName = courseDto.CourseName,
                Description = courseDto.Description,
                TeacherId = teacher.TeacherId // Assign the existing teacher to the course
            };

            _context.Courses.Add(course);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetCourseById), new { id = course.CourseId }, courseDto);
        }

        // 4. Update an Existing Course with Teacher information
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateCourse(int id, [FromBody] CourseDTO courseDto)
        {
            var course = await _context.Courses.FindAsync(id);
            if (course == null) return NotFound();

            // Ensure teacher exists before updating
            var teacher = await _context.Teachers.FindAsync(courseDto.Teacher.TeacherId);
            if (teacher == null) return BadRequest("Teacher not found");

            course.CourseName = courseDto.CourseName;
            course.Description = courseDto.Description;
            course.TeacherId = teacher.TeacherId;

            await _context.SaveChangesAsync();
            return Ok(courseDto);
        }

        // 5. Delete a Course
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteCourse(int id)
        {
            var course = await _context.Courses.FindAsync(id);
            if (course == null) return NotFound();

            _context.Courses.Remove(course);
            await _context.SaveChangesAsync();

            return NoContent();
        }

    }
}
