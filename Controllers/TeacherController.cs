using Institute_Management.DTOs;
using Institute_Management.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using static Institute_Management.Models.CourseModule;
using static Institute_Management.Models.StudentModule;
using static Institute_Management.Models.TeacherModule;
using static Institute_Management.Models.UserModule;

namespace Institute_Management.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TeacherController : ControllerBase
    {
        private readonly InstituteContext _context;

        public TeacherController(InstituteContext context)
        {
            _context = context;
        }

        // GET: api/teacher
        [HttpGet]
        public async Task<IActionResult> GetTeachers()
        {
            // Fetch all teachers along with their related courses
            var teachers = await _context.Teachers
                .Include(t => t.Courses) // Assuming a Teacher has a collection of Courses
                .Include(t => t.User)
                .ToListAsync();


            // Create a list of TeacherDTOs
            var teacherDtos = teachers.Select(t => new TeacherDTO
            {
                TeacherId = (int)t.TeacherId,
                User = t.User != null ? new UserDTO
                {
                    UserId = (int)t.User.UserId,
                    Name = t.User.Name,
                    Email = t.User.Email,
                    Role = t.User.Role,
                    ContactDetails = t.User.ContactDetails
                } : null, // Handle the case where User is null
                Courses = t.Courses != null ? t.Courses.Select(c => new CourseDTO
                {
                    CourseId = (int)c.CourseId,
                    CourseName = c.CourseName,
                    Description = c.Description,
                    //Teacher = c.Teacher,
                }).ToList() : new List<CourseDTO>() // Handle the case where Courses is null
            }).ToList();


            return Ok(teacherDtos);
        }

        // GET: api/teacher/{id}
        [HttpGet("{id}")]
        public async Task<IActionResult> GetTeacher(int id)
        {
            // Fetch the teacher along with their related courses
            var teacher = await _context.Teachers
                .Include(t => t.Courses) // Assuming a Teacher has a collection of Courses
                .Include(t => t.User)
                .FirstOrDefaultAsync(t => t.TeacherId == id);

            if (teacher == null) return NotFound();

            // Create a TeacherDTO
            var teacherDto = new TeacherDTO
            {
                TeacherId = (int)teacher.TeacherId,
                UserId = teacher.UserId,
                SubjectSpecialization = teacher.SubjectSpecialization,
                User = new UserDTO
                {
                    UserId = (int)teacher.UserId,
                    Name = teacher.User.Name,
                    Email = teacher.User.Email,
                    Role = teacher.User.Role,
                    ContactDetails = teacher.User.ContactDetails
                },
                Courses = teacher.Courses.Select(c => new CourseDTO
                {
                    CourseId = (int)c.CourseId,
                    CourseName = c.CourseName,
                    Description = c.Description,
                    //Teacher = c.Teacher,
                }).ToList()
            
            //Name = teacher.Name,
            //    Email = teacher.Email,
            //    PhoneNumber = teacher.PhoneNumber,
            //    Address = teacher.Address,
            //    Courses = teacher.Courses.Select(c => new CourseDto
            //    {
            //        Id = c.Id,
            //        CourseName = c.CourseName,
            //        Description = c.Description,
            //        TeacherId = c.TeacherId,
            //    }).ToList()
            };

            return Ok(teacherDto);
        }

        // POST: api/teacher
        [HttpPost]
        public async Task<ActionResult<TeacherDTO>> PostTeacher([FromBody] TeacherDTO teacherDto)
        {
            if (teacherDto == null)
            {
                return BadRequest("Invalid teacher data.");
            }

            // Check if User and Courses are provided, but don't fail if they're null
            if (teacherDto.User == null)
            {
                return BadRequest("Missing required field: User.");
            }

            // If courses are provided, map them but avoid adding the Teacher reference to prevent cycle
            var teacher = new Teacher
            {
                // Mapping the User
                User = teacherDto.User != null ? new User
                {
                    UserId = teacherDto.User.UserId,
                    Name = teacherDto.User.Name,
                    Email = teacherDto.User.Email,
                    Role = teacherDto.User.Role,
                    ContactDetails = teacherDto.User.ContactDetails
                } : null,

                // Map courses but avoid linking teacher to courses to prevent cycles
                Courses = teacherDto.Courses != null ? teacherDto.Courses.Select(c => new Course
                {
                    CourseName = c.CourseName,
                    Description = c.Description,
                    // Avoid setting the Teacher reference here to prevent cyclic reference
                }).ToList() : new List<Course>()
            };

            // Add teacher entity to the context and save changes
            _context.Teachers.Add(teacher);
            await _context.SaveChangesAsync();

            // Return the created teacher in the response (avoid returning entire courses or teacher references)
            var teacherResponseDto = new TeacherDTO
            {
                TeacherId = teacher.TeacherId,
                User = new UserDTO
                {
                    UserId = teacher.User.UserId,
                    Name = teacher.User.Name,
                    Email = teacher.User.Email,
                    Role = teacher.User.Role,
                    ContactDetails = teacher.User.ContactDetails
                },
                Courses = teacher.Courses.Select(c => new CourseDTO
                {
                    CourseId = c.CourseId,
                    CourseName = c.CourseName,
                    Description = c.Description,
                }).ToList()
            };

            return CreatedAtAction(nameof(GetTeacher), new { id = teacher.TeacherId }, teacherResponseDto);
        }





        // PUT: api/teacher/{id}
        [HttpPut("{id}")]
        public async Task<IActionResult> PutTeacher(int id, Teacher teacher)
        {
            if (id != teacher.TeacherId)
            {
                return BadRequest();
            }

            _context.Entry(teacher).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!TeacherExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // DELETE: api/teacher/{id}
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteTeacher(int id)
        {
            var teacher = await _context.Teachers
                .Include(t => t.Courses)  // Include related courses to handle them
                .FirstOrDefaultAsync(t => t.TeacherId == id);

            if (teacher == null)
            {
                return NotFound();
            }

            // Set TeacherId to null for each course related to this teacher
            foreach (var course in teacher.Courses)
            {
                course.TeacherId = null;  // This makes the foreign key nullable
            }

            _context.Teachers.Remove(teacher);
            await _context.SaveChangesAsync();

            return NoContent();
        }



        private bool TeacherExists(int id)
        {
            return _context.Teachers.Any(e => e.TeacherId == id);
        }
    }
}
