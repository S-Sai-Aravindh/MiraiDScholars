using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Institute_Management.Models;
using System.Collections.Generic;
using System.Threading.Tasks;
using Institute_Management.Services;
using static Institute_Management.Models.UserModule;
using Institute_Management.DTOs;

namespace Institute_Management.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly InstituteContext _context;
        private readonly JwtService _jwtService;

        public AuthController(InstituteContext context, JwtService jwtService)
        {
            _context = context;
            _jwtService = jwtService;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserModule.User>>> GetUsers()
        {
            return await _context.Users.ToListAsync();
        }

        [HttpGet("Alldetails")]
        public async Task<ActionResult<IEnumerable<object>>> GetAllUsers()
        {
            var users = await _context.Users.ToListAsync();

            var userDtos = users.Select(user => new
            {
                UserId = user.UserId,
                Name = user.Name,
                Email = user.Email,
                Role = user.Role,
                ContactDetails = user.ContactDetails,
                StudentId = _context.Students
                    .Where(s => s.UserId == user.UserId)
                    .Select(s => s.StudentId)
                    .FirstOrDefault(),
                TeacherId = _context.Teachers
                    .Where(t => t.UserId == user.UserId)
                    .Select(t => t.TeacherId)
                    .FirstOrDefault()
            }).ToList();

            return Ok(userDtos);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> AuthenticateUser([FromQuery] string email, [FromQuery] string password)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                return BadRequest(new { message = "Email and Password are required." });
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            if (user.Password != password) // Note: In a real application, always hash passwords
            {
                return Unauthorized(new { message = "Invalid credentials." });
            }

            var userDto = new UserDTO
            {
                UserId = (int)user.UserId,
                Name = user.Name,
                Email = user.Email,
                Role = user.Role,
                ContactDetails = user.ContactDetails
            };


            // Fetch the associated Student record if the user is a student
            var student = await _context.Students.FirstOrDefaultAsync(s => s.UserId == user.UserId);

            StudentDTO studentDto = null;
            if (student != null)
            {
                studentDto = new StudentDTO
                {
                    StudentId = student.StudentId,
                    UserId = student.UserId,
                    BatchId = student.BatchId,
                    User = userDto, // Including UserDTO in StudentDTO
                    Enrollments = student.Enrollments.Select(e => new EnrollmentDTO { /* mapping enrollments */ }).ToList()
                };
            }

            // Fetch the associated Teacher record if the user is a teacher
            var teacher = await _context.Teachers.FirstOrDefaultAsync(t => t.UserId == user.UserId);

            TeacherDTO teacherDto = null;
            if (teacher != null)
            {
                teacherDto = new TeacherDTO
                {
                    TeacherId = teacher.TeacherId,
                    UserId = teacher.UserId,
                    SubjectSpecialization = teacher.SubjectSpecialization,
                    User = userDto,
                    Courses = teacher.Courses.Select(c => new CourseDTO { /* mapping courses */ }).ToList()
                };
            }



            return Ok(new
            {
                message = "Login successful",
                User = userDto,
                Student = studentDto, // Include StudentDTO if the user is a student
                Teacher = teacherDto   // Include TeacherDTO if the user is a teacher
            });
        }


        [HttpPost("login")]
        public async Task<IActionResult> Authenticate([FromBody] LoginDTO request)
        {
            if (request == null || string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { message = "Email and Password are required." });
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            if (user.Password != request.Password)
            {
                return Unauthorized(new { message = "Invalid credentials." });
            }

            var token = _jwtService.GenerateToken(user);
            return Ok(new { message = "Login successful", token });
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateUser(int id, [FromBody] UserDTO userDTO)
        {
            // Validate input
            if (userDTO == null)
            {
                return BadRequest(new { message = "Invalid user data." });
            }

            // Fetch the user by ID
            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserId == id);

            // Check if user exists
            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            // If the entity is not tracked, attach it to the context
            _context.Entry(user).State = EntityState.Modified;

            // Update the user details
            user.Name = userDTO.Name;
            user.Email = userDTO.Email;
            user.ContactDetails = userDTO.ContactDetails;
            user.Role = userDTO.Role;

            // Save changes to the database
            var changes = await _context.SaveChangesAsync();

            if (changes == 0)
            {
                return BadRequest(new { message = "No changes were saved to the database." });
            }

            return Ok(new
            {
                message = "User updated successfully",
                User = userDTO
            });
        }




        [Authorize(Roles = "Admin")]
        [HttpGet("admin-data")]
        public async Task<IActionResult> GetAdminData()
        {
            // Fetch admin details including the associated user (eager loading)
            var admin = await _context.Admins
                .Include(a => a.User)  // Ensure user data is included with admin data
                .FirstOrDefaultAsync(a => a.User.Role == "Admin");

            // Check if admin data exists
            if (admin == null)
            {
                return NotFound(new { message = "Admin data not found" });
            }

            // Map the Admin and User data to AdminDTO and UserDTO
            var adminDTO = new AdminDTO
            {
                AdminId = admin.AdminId,
                UserId = admin.UserId,
                User = new UserDTO
                {
                    UserId = admin.User.UserId,
                    Name = admin.User.Name,
                    Email = admin.User.Email,
                    Role = admin.User.Role,
                    ContactDetails = admin.User.ContactDetails
                }
            };

            return Ok(adminDTO);  // Return AdminDTO with user details
        }

        


        [Authorize(Roles = "Teacher,Admin")]
        [HttpGet("teacher-data")]
        public IActionResult GetTeacherData()
        {
            return Ok(new { message = "This is teacher and admin accessible data" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User user)
        {
            if (user == null || string.IsNullOrEmpty(user.Email) || string.IsNullOrEmpty(user.Password))
            {
                return BadRequest(new { message = "Invalid input. Email and Password are required." });
            }

            if (await _context.Users.AnyAsync(u => u.Email == user.Email))
            {
                return Conflict(new { message = "User already exists." });
            }

            try
            {
                _context.Users.Add(user);
                await _context.SaveChangesAsync(); // Save the user first to generate UserId

                // Based on the role, insert into the respective table
                if (user.Role == "Student")
                {
                    var student = new StudentModule.Student
                    {
                        UserId = user.UserId // Ensure that the UserId is set
                    };
                    _context.Students.Add(student);
                    await _context.SaveChangesAsync();
                }
                else if (user.Role == "Teacher")
                {
                    var teacher = new TeacherModule.Teacher
                    {
                        UserId = user.UserId // Ensure that the UserId is set
                    };
                    _context.Teachers.Add(teacher);
                    await _context.SaveChangesAsync();
                }

                return CreatedAtAction(nameof(Register), new { id = user.UserId }, new { message = "Registration successful" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    message = "An error occurred while processing your request.",
                    error = ex.Message,
                    suggestion = "Ensure the API URL is correct and the server is running."
                });
            }
        }



    }
}
