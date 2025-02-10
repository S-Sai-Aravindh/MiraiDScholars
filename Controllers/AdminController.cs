using Institute_Management.DTOs;
using Institute_Management.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using static Institute_Management.Models.BatchModule;
using static Institute_Management.Models.CourseModule;
using static Institute_Management.Models.StudentModule;
using static Institute_Management.Models.TeacherModule;
using static Institute_Management.Models.UserModule;

namespace Institute_Management.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private readonly InstituteContext _context;

        public AdminController(InstituteContext context)
        {
            _context = context;
        }

        #region Students Management

        // GET: api/admin/students
        [HttpGet("students")]
        public async Task<ActionResult<IEnumerable<StudentDTO>>> GetAllStudents()
        {
            var students = await _context.Students
                .Include(s => s.User)
                .Include(s => s.Batch)
                    .ThenInclude(b => b.Courses) // Include Courses in Batch
                .Include(s => s.Enrollments)
                    .ThenInclude(e => e.Course)
                        .ThenInclude(c => c.Teacher)
                            .ThenInclude(t => t.User)
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
                    Batch = new BatchDTO
                    {
                        BatchName = s.Batch.BatchName,
                        BatchTiming = s.Batch.BatchTiming,
                        BatchType = s.Batch.BatchType,
                        Course = new CourseDTO
                        {
                            CourseId = (int)s.Batch.CourseId,
                            CourseName = s.Batch.Course.CourseName,
                            Description = s.Batch.Course.Description,
                            Teacher = new TeacherDTO
                            {
                                TeacherId = (int)s.Batch.Course.TeacherId,
                                UserId = (int)s.UserId,
                                SubjectSpecialization = s.Batch.Course.Teacher.SubjectSpecialization
                            }
                        }
                    },
                    Enrollments = s.Enrollments.Select(e => new EnrollmentDTO
                    {
                        StudentId = (int)e.StudentId,
                        CourseId = (int)e.CourseId,
                        Course = new CourseDTO
                        {
                            CourseId = (int)e.Course.CourseId,
                            CourseName = e.Course.CourseName,
                            Description = e.Course.Description,
                            Teacher = e.Course.Teacher != null ? new TeacherDTO
                            {
                                TeacherId = (int)e.Course.Teacher.TeacherId,
                                UserId = (int)e.Course.Teacher.UserId,
                                SubjectSpecialization = e.Course.Teacher.SubjectSpecialization,
                                User = new UserDTO
                                {
                                    UserId = (int)e.Course.Teacher.User.UserId,
                                    Name = e.Course.Teacher.User.Name,
                                    Email = e.Course.Teacher.User.Email,
                                    Role = e.Course.Teacher.User.Role,
                                    ContactDetails = e.Course.Teacher.User.ContactDetails
                                }
                            } : null
                        }
                    }).ToList()
                })
                .ToListAsync();

            return Ok(students);
        }



        [HttpGet("students/{id}")]
        public async Task<IActionResult> GetStudentById(int id)
        {
            var student = await _context.Students
                .Include(s => s.User)
                .Include(s => s.Batch)
                .Include(s => s.Enrollments)
                .ThenInclude(e => e.Course)
                .FirstOrDefaultAsync(s => s.StudentId == id);

            if (student == null) return NotFound();

            var studentDto = new StudentDTO
            {
                StudentId = (int)student.StudentId,
                UserId = (int)student.UserId,
                BatchId = student.BatchId,
                User = student.User != null ? new UserDTO
                {
                    UserId = (int)student.User.UserId,
                    Name = student.User.Name,
                    Email = student.User.Email,
                    Role = student.User.Role,
                    ContactDetails = student.User.ContactDetails
                } : null,
                Batch = student.Batch != null ? new BatchDTO
                {
                    BatchId = (int)student.Batch.BatchId,
                    BatchName = student.Batch.BatchName,
                    BatchTiming = student.Batch.BatchTiming,
                    BatchType = student.Batch.BatchType,
                    Course = student.Batch.Course != null ? new CourseDTO
                    {
                        CourseId = (int)student.Batch.Course.CourseId,
                        CourseName = student.Batch.Course.CourseName,
                        Description = student.Batch.Course.Description
                    } : null
                } : null,
                Enrollments = student.Enrollments.Select(e => new EnrollmentDTO
                {
                    StudentId = (int)e.StudentId,
                    CourseId = (int)e.CourseId,
                    Course = e.Course != null ? new CourseDTO
                    {
                        CourseId = (int)e.Course.CourseId,
                        CourseName = e.Course.CourseName,
                        Description = e.Course.Description,
                        Teacher = e.Course.Teacher != null ? new TeacherDTO
                        {
                            TeacherId = (int)e.Course.Teacher.TeacherId,
                            UserId = (int)e.Course.Teacher.UserId,
                            SubjectSpecialization = e.Course.Teacher.SubjectSpecialization
                        } : null
                    } : null
                }).ToList()
            };


            return Ok(studentDto);
        }


        // POST: api/admin/students
        [HttpPost("students")]
        public async Task<ActionResult<StudentDTO>> CreateStudent([FromBody] StudentDTO studentDto)
        {
            if (studentDto == null)
            {
                return BadRequest("Invalid student data.");
            }

            // Check for User and Batch (and Course/Teacher if provided), but don't fail if they're null
            if (studentDto.User == null)
            {
                return BadRequest("Missing required field: User.");
            }

            if (studentDto.Batch == null)
            {
                return BadRequest("Missing required field: Batch.");
            }

            if (studentDto.Batch.Course != null && studentDto.Batch.Course.Teacher == null)
            {
                return BadRequest("Missing required field: Teacher in Course.");
            }

            // If all required fields are valid or optional, proceed with creating the student.
            var student = new Student
            {
                User = studentDto.User != null ? new User
                {
                    UserId = studentDto.User.UserId,
                    Name = studentDto.User.Name,
                    Email = studentDto.User.Email,
                    Role = studentDto.User.Role,
                    ContactDetails = studentDto.User.ContactDetails
                } : null,

                Batch = studentDto.Batch != null ? new Batch
                {
                    BatchName = studentDto.Batch.BatchName,
                    BatchType = studentDto.Batch.BatchType,
                    BatchTiming = studentDto.Batch.BatchTiming,
                    Course = studentDto.Batch.Course != null ? new Course
                    {
                        CourseName = studentDto.Batch.Course.CourseName,
                        Description = studentDto.Batch.Course.Description,
                        Teacher = studentDto.Batch.Course.Teacher != null ? new Teacher
                        {
                            User = studentDto.Batch.Course.Teacher.User != null ? new User
                            {
                                UserId = studentDto.Batch.Course.Teacher.User.UserId,
                                Name = studentDto.Batch.Course.Teacher.User.Name,
                                Email = studentDto.Batch.Course.Teacher.User.Email,
                                Role = studentDto.Batch.Course.Teacher.User.Role,
                                ContactDetails = studentDto.Batch.Course.Teacher.User.ContactDetails
                            } : null,
                            SubjectSpecialization = studentDto.Batch.Course.Teacher.SubjectSpecialization
                        } : null
                    } : null
                } : null,

                Enrollments = studentDto.Enrollments?.Select(e => new StudentCourseModule.StudentCourse
                {
                    Course = new Course
                    {
                        CourseName = e.Course.CourseName,
                        Description = e.Course.Description,
                        Teacher = e.Course.Teacher != null ? new Teacher
                        {
                            SubjectSpecialization = e.Course.Teacher.SubjectSpecialization
                        } : null
                    }
                }).ToList()
            };

            _context.Students.Add(student);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetAllStudents), new { id = student.StudentId }, studentDto);
        }





        // PUT: api/admin/students/{id}
        [HttpPut("students/{id}")]
        public async Task<IActionResult> UpdateStudent(int id, [FromBody] StudentDTO studentDto)
        {
            if (studentDto == null)
                return BadRequest("Student data is missing.");

            var student = await _context.Students
                .Include(s => s.User)
                .Include(s => s.Enrollments)
                .FirstOrDefaultAsync(s => s.StudentId == id);

            if (student == null)
                return NotFound();

            // Update User details if provided
            if (studentDto.User != null)
            {
                student.User.Name = studentDto.User.Name ?? student.User.Name;
                student.User.Email = studentDto.User.Email ?? student.User.Email;
                student.User.Role = studentDto.User.Role ?? student.User.Role;
                student.User.ContactDetails = studentDto.User.ContactDetails ?? student.User.ContactDetails;
            }

            // Update Batch if provided and valid
            if (studentDto.BatchId.HasValue)
            {
                var batch = await _context.Batches.FindAsync(studentDto.BatchId);
                if (batch != null)
                {
                    student.BatchId = batch.BatchId;
                }
                else
                {
                    return BadRequest("Invalid Batch ID.");
                }
            }

            // Update Enrollments if provided
            if (studentDto.Enrollments != null && studentDto.Enrollments.Any())
            {
                // Ensure the student's Enrollments collection is initialized
                if (student.Enrollments == null)
                {
                    student.Enrollments = new List<StudentCourseModule.StudentCourse>();
                }
                else
                {
                    student.Enrollments.Clear(); // Clear existing enrollments
                }

                foreach (var enrollmentDto in studentDto.Enrollments)
                {
                    if (enrollmentDto.CourseId.HasValue) // Ensure CourseId is not null
                    {
                        var course = await _context.Courses.FindAsync(enrollmentDto.CourseId);
                        if (course != null)
                        {
                            student.Enrollments.Add(new StudentCourseModule.StudentCourse { StudentId = student.StudentId, CourseId = course.CourseId });
                        }
                    }
                }
            }


            await _context.SaveChangesAsync();
            return NoContent();
        }



        // DELETE: api/admin/students/{id}
        [HttpDelete("students/{id}")]
        public async Task<IActionResult> DeleteStudent(int id)
        {
            var student = await _context.Students.FindAsync(id);
            if (student == null) return NotFound();

            _context.Students.Remove(student);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        #endregion

        #region Teacher Management

        // GET: api/admin/teachers
        [HttpGet("teachers")]
        public async Task<ActionResult<IEnumerable<TeacherDTO>>> GetAllTeachers()
        {
            var teachers = await _context.Teachers
                .Include(t => t.User)
                .Include(t => t.Courses) // Include the related courses
                .Select(t => new TeacherDTO
                {
                    TeacherId = (int)t.TeacherId,
                    UserId = (int)t.UserId,
                    SubjectSpecialization = t.SubjectSpecialization,
                    User = new UserDTO
                    {
                        UserId = (int)t.User.UserId,
                        Name = t.User.Name,
                        Email = t.User.Email,
                        Role = t.User.Role,
                        ContactDetails = t.User.ContactDetails
                    },
                    Courses = t.Courses.Select(c => new CourseDTO
                    {
                        CourseId = (int)c.CourseId,
                        CourseName = c.CourseName,
                        Description = c.Description
                    }).ToList() // Fetching the courses details for each teacher
                })
                .ToListAsync();

            return Ok(teachers);
        }


        [HttpGet("teachers/{id}")]
        public async Task<ActionResult<TeacherDTO>> GetTeacherById(int id)
        {
            var teacher = await _context.Teachers
                .Include(t => t.User)
                .Where(t => t.TeacherId == id)
                .Select(t => new TeacherDTO
                {
                    TeacherId = (int)t.TeacherId,
                    UserId = (int)t.UserId,
                    SubjectSpecialization = t.SubjectSpecialization,
                    User = new UserDTO
                    {
                        UserId = (int)t.User.UserId,
                        Name = t.User.Name,
                        Email = t.User.Email,
                        Role = t.User.Role,
                        ContactDetails = t.User.ContactDetails
                    }
                })
                .FirstOrDefaultAsync();

            if (teacher == null)
                return NotFound(); // Return 404 if no teacher is found

            return Ok(teacher); // Return 200 with the teacher data
        }


        // POST: api/admin/teachers
        [HttpPost("teachers")]
        public async Task<ActionResult<TeacherDTO>> CreateTeacher([FromBody] TeacherDTO teacherDto)
        {
            // Check if the user exists
            var user = await _context.Users.FindAsync(teacherDto.UserId);
            if (user == null)
            {
                return BadRequest("User not found.");
            }

            // Create the teacher object
            var teacher = new TeacherModule.Teacher
            {
                UserId = teacherDto.UserId,
                SubjectSpecialization = teacherDto.SubjectSpecialization,
                User = new UserModule.User  // Associate the user data
                {
                    Name = teacherDto.User.Name,
                    Email = teacherDto.User.Email,
                    Role = teacherDto.User.Role,
                    ContactDetails = teacherDto.User.ContactDetails
                }
            };

            // Add the new teacher to the context
            _context.Teachers.Add(teacher);
            await _context.SaveChangesAsync();

            // Return the created teacher DTO
            return CreatedAtAction(nameof(GetAllTeachers), new { id = teacher.TeacherId }, teacherDto);
        }

        // PUT: api/admin/teachers/{id}
        [HttpPut("teachers/{id}")]
        public async Task<IActionResult> UpdateTeacher(int id, [FromBody] TeacherDTO teacherDto)
        {
            // Find the teacher
            var teacher = await _context.Teachers
                .Include(t => t.User)
                .Include(t => t.Courses)
                .FirstOrDefaultAsync(t => t.TeacherId == id);
            if (teacher == null)
            {
                return NotFound();
            }

            // Validate SubjectSpecialization
            if (string.IsNullOrEmpty(teacherDto.SubjectSpecialization))
            {
                return BadRequest("SubjectSpecialization cannot be null or empty.");
            }

            // Update Teacher details
            teacher.UserId = teacherDto.User.UserId;
            teacher.SubjectSpecialization = teacherDto.SubjectSpecialization;

            // Ensure that the User exists and update user information
            if (teacher.User == null)
            {
                // If User does not exist, you can either return a BadRequest or create a new user.
                // Here, let's assume we need to create a new user if it doesn't exist.
                var user = new User
                {
                    UserId = teacherDto.User.UserId,
                    Name = teacherDto.User.Name,
                    Email = teacherDto.User.Email,
                    Role = teacherDto.User.Role,
                    ContactDetails = teacherDto.User.ContactDetails
                };
                _context.Users.Add(user); // Add the new user to the database
                teacher.User = user; // Assign the new user to the teacher
            }
            else
            {
                // If the User exists, update their details
                teacher.User.Name = teacherDto.User.Name;
                teacher.User.Email = teacherDto.User.Email;
                teacher.User.Role = teacherDto.User.Role;
                teacher.User.ContactDetails = teacherDto.User.ContactDetails;
            }

            // Update courses
            if (teacherDto.Courses != null)
            {
                // Remove existing courses that are not in the new list
                foreach (var course in teacher.Courses.ToList())
                {
                    if (!teacherDto.Courses.Any(c => c.CourseId == course.CourseId))
                    {
                        teacher.Courses.Remove(course);
                    }
                }

                // Add new courses
                foreach (var courseDto in teacherDto.Courses)
                {
                    var existingCourse = teacher.Courses.FirstOrDefault(c => c.CourseId == courseDto.CourseId);
                    if (existingCourse == null)
                    {
                        var newCourse = new Course
                        {
                            CourseId = courseDto.CourseId,
                            CourseName = courseDto.CourseName,
                            TeacherId = teacher.TeacherId
                        };
                        teacher.Courses.Add(newCourse);
                    }
                    else
                    {
                        existingCourse.CourseName = courseDto.CourseName;
                    }
                }
            }

            // Save changes to the database
            await _context.SaveChangesAsync();

            // Return the updated teacher data
            return Ok(teacher);
        }





        // DELETE: api/admin/teachers/{id}
        //Teacher delete not possible as if there is teacher then only course
        [HttpDelete("teachers/{id}")]
        public async Task<IActionResult> DeleteTeacher(int id)
        {
            var teacher = await _context.Teachers
                .Include(t => t.Courses) // Include courses related to the teacher
                .Include(t => t.User)    // Include the user related to the teacher
                .FirstOrDefaultAsync(t => t.TeacherId == id);

            if (teacher == null) return NotFound();

            // Set TeacherId to null for all courses related to this teacher
            foreach (var course in teacher.Courses)
            {
                course.TeacherId = null;
            }

            // Update the courses with null TeacherId
            _context.Courses.UpdateRange(teacher.Courses);

            // Remove the teacher from the Teachers table
            _context.Teachers.Remove(teacher);

            // If a related user exists, remove the user as well
            if (teacher.User != null)
            {
                _context.Users.Remove(teacher.User);
            }

            // Save the changes
            await _context.SaveChangesAsync();

            return NoContent();
        }




        #endregion

        #region Course Management

        // GET: api/admin/courses
        [HttpGet("courses")]
        public async Task<ActionResult<IEnumerable<CourseDTO>>> GetAllCourses()
        {
            var courses = await _context.Courses
                .Include(c => c.Teacher)
                .ThenInclude(t => t.User)
                .Select(c => new CourseDTO
                {
                    CourseId = (int)c.CourseId,
                    CourseName = c.CourseName,
                    Description = c.Description,
                    //TeacherId = c.TeacherId,
                    Teacher = new TeacherDTO
                    {
                        TeacherId = (int)c.Teacher.TeacherId,
                        UserId = (int)c.Teacher.UserId,
                        SubjectSpecialization = c.Teacher.SubjectSpecialization,
                        User = new UserDTO
                        {
                            UserId = (int)c.Teacher.User.UserId,
                            Name = c.Teacher.User.Name,
                            Email = c.Teacher.User.Email,
                            Role = c.Teacher.User.Role,
                            ContactDetails = c.Teacher.User.ContactDetails,
                        }
                    }
                })
                .ToListAsync();

            return Ok(courses);
        }

        // GET: api/admin/courses/{id}
        [HttpGet("courses/{id}")]
        public async Task<ActionResult<CourseDTO>> GetCourseById(int id)
        {
            var course = await _context.Courses
                .Include(c => c.Teacher)
                .ThenInclude(t => t.User)
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
                        SubjectSpecialization = c.Teacher.SubjectSpecialization,
                        User = new UserDTO
                        {
                            UserId = (int)c.Teacher.User.UserId,
                            Name = c.Teacher.User.Name,
                            Email = c.Teacher.User.Email,
                            Role = c.Teacher.User.Role,
                            ContactDetails = c.Teacher.User.ContactDetails,
                        }
                    }
                })
                .FirstOrDefaultAsync();

            if (course == null)
            {
                return NotFound();
            }

            return Ok(course);
        }


        // POST: api/admin/courses
        [HttpPost("courses")]
        public async Task<ActionResult<CourseDTO>> CreateCourse([FromBody] CourseDTO courseDto)
        {
            // Check if Teacher exists, otherwise handle it
            var teacher = await _context.Teachers
                .Include(t => t.User)
                .FirstOrDefaultAsync(t => t.TeacherId == courseDto.Teacher.TeacherId);

            if (teacher == null)
            {
                return BadRequest("Teacher does not exist.");
            }

            var course = new CourseModule.Course
            {
                CourseName = courseDto.CourseName,
                Description = courseDto.Description,
                TeacherId = teacher.TeacherId // Set TeacherId from the provided teacher information
            };

            _context.Courses.Add(course);
            await _context.SaveChangesAsync();

            // Return the created course with Teacher data
            var createdCourseDto = new CourseDTO
            {
                CourseId = course.CourseId,
                CourseName = course.CourseName,
                Description = course.Description,
                Teacher = new TeacherDTO
                {
                    TeacherId = teacher.TeacherId,
                    UserId = teacher.UserId,
                    SubjectSpecialization = teacher.SubjectSpecialization,
                    User = new UserDTO
                    {
                        UserId = teacher.User.UserId,
                        Name = teacher.User.Name,
                        Email = teacher.User.Email,
                        Role = teacher.User.Role,
                        ContactDetails = teacher.User.ContactDetails
                    }
                }
            };

            return CreatedAtAction(nameof(GetAllCourses), new { id = course.CourseId }, createdCourseDto);
        }


        // PUT: api/admin/courses/{id}
        [HttpPut("courses/{id}")]
        public async Task<IActionResult> UpdateCourse(int id, [FromBody] CourseDTO courseDto)
        {
            var course = await _context.Courses.Include(c => c.Teacher).ThenInclude(t => t.User).FirstOrDefaultAsync(c => c.CourseId == id);
            if (course == null) return NotFound();

            // Update course details
            course.CourseName = courseDto.CourseName;
            course.Description = courseDto.Description;

            // Check if the teacher exists, and update teacher data
            if (courseDto.Teacher != null)
            {
                var teacher = await _context.Teachers.Include(t => t.User).FirstOrDefaultAsync(t => t.TeacherId == courseDto.Teacher.TeacherId);

                if (teacher != null)
                {
                    // Update teacher information
                    teacher.SubjectSpecialization = courseDto.Teacher.SubjectSpecialization;
                    teacher.User.Name = courseDto.Teacher.User.Name;
                    teacher.User.Email = courseDto.Teacher.User.Email;
                    teacher.User.ContactDetails = courseDto.Teacher.User.ContactDetails;
                    teacher.User.Role = courseDto.Teacher.User.Role;

                    // Optionally update the teacher's User data if needed
                    _context.Update(teacher);
                }
                else
                {
                    return BadRequest("Teacher does not exist.");
                }
            }

            // Save changes
            await _context.SaveChangesAsync();
            return NoContent();
        }


        // DELETE: api/admin/courses/{id}
        [HttpDelete("courses/{id}")]
        public async Task<IActionResult> DeleteCourse(int id)
        {
            var course = await _context.Courses.FindAsync(id);
            if (course == null) return NotFound();

            _context.Courses.Remove(course);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        #endregion

        #region Batch Management    

        // GET: api/admin/batches
        [HttpGet("batches")]
        public async Task<ActionResult<IEnumerable<BatchDTO>>> GetAllBatches()
        {
            var batches = await _context.Batches
                .Include(b => b.Course)
                .ThenInclude(c => c.Teacher) // Ensure Teacher is included
                .ThenInclude(t => t.User) // Include User details inside Teacher
                .Select(b => new BatchDTO
                {
                    BatchId = (int)b.BatchId,
                    BatchName = b.BatchName,
                    BatchTiming = b.BatchTiming,
                    BatchType = b.BatchType,
                    Course = new CourseDTO
                    {
                        CourseId = (int)b.Course.CourseId,
                        CourseName = b.Course.CourseName,
                        Description = b.Course.Description,
                        Teacher = new TeacherDTO
                        {
                            TeacherId = (int)b.Course.Teacher.TeacherId,
                            UserId = (int)b.Course.Teacher.UserId,
                            SubjectSpecialization = b.Course.Teacher.SubjectSpecialization,
                            User = new UserDTO
                            {
                                UserId = (int)b.Course.Teacher.User.UserId,
                                Name = b.Course.Teacher.User.Name,
                                Email = b.Course.Teacher.User.Email,
                                Role = b.Course.Teacher.User.Role,
                                ContactDetails = b.Course.Teacher.User.ContactDetails
                            }
                        }
                    }
                })
                .ToListAsync();

            return Ok(batches);
        }

        [HttpGet("batches/{id}")]
        public async Task<ActionResult<BatchDTO>> GetBatchById(int id)
        {
            var batch = await _context.Batches
                .Include(b => b.Course)
                .ThenInclude(c => c.Teacher) // Ensure Teacher is included
                .ThenInclude(t => t.User) // Include User details inside Teacher
                .Where(b => b.BatchId == id)
                .Select(b => new BatchDTO
                {
                    BatchId = (int)b.BatchId,
                    BatchName = b.BatchName,
                    BatchTiming = b.BatchTiming,
                    BatchType = b.BatchType,
                    Course = new CourseDTO
                    {
                        CourseId = (int)b.Course.CourseId,
                        CourseName = b.Course.CourseName,
                        Description = b.Course.Description,
                        Teacher = new TeacherDTO
                        {
                            TeacherId = (int)b.Course.Teacher.TeacherId,
                            UserId = (int)b.Course.Teacher.UserId,
                            SubjectSpecialization = b.Course.Teacher.SubjectSpecialization,
                            User = new UserDTO
                            {
                                UserId = (int)b.Course.Teacher.User.UserId,
                                Name = b.Course.Teacher.User.Name,
                                Email = b.Course.Teacher.User.Email,
                                Role = b.Course.Teacher.User.Role,
                                ContactDetails = b.Course.Teacher.User.ContactDetails
                            }
                        }
                    }
                })
                .FirstOrDefaultAsync();

            if (batch == null)
            {
                return NotFound();
            }

            return Ok(batch);
        }


        // POST: api/admin/batches
        [HttpPost("batches")]
        public async Task<ActionResult<BatchDTO>> CreateBatch([FromBody] BatchDTO batchDto)
        {
            // Check if the course exists, otherwise handle it
            var course = await _context.Courses
                .Include(c => c.Teacher)
                .ThenInclude(t => t.User)
                .FirstOrDefaultAsync(c => c.CourseId == batchDto.Course.CourseId);

            if (course == null)
            {
                return BadRequest("Course does not exist.");
            }

            var batch = new BatchModule.Batch
            {
                BatchName = batchDto.BatchName,
                BatchTiming = batchDto.BatchTiming,
                BatchType = batchDto.BatchType,
                CourseId = course.CourseId // Set CourseId from the provided course information
            };

            _context.Batches.Add(batch);
            await _context.SaveChangesAsync();

            // Return the created batch with Course data
            var createdBatchDto = new BatchDTO
            {
                BatchId = batch.BatchId,
                BatchName = batch.BatchName,
                BatchTiming = batch.BatchTiming,
                BatchType = batch.BatchType,
                Course = new CourseDTO
                {
                    CourseId = course.CourseId,
                    CourseName = course.CourseName,
                    Description = course.Description,
                    Teacher = new TeacherDTO
                    {
                        TeacherId = course.Teacher.TeacherId,
                        UserId = course.Teacher.UserId,
                        SubjectSpecialization = course.Teacher.SubjectSpecialization,
                        User = new UserDTO
                        {
                            UserId = course.Teacher.User.UserId,
                            Name = course.Teacher.User.Name,
                            Email = course.Teacher.User.Email,
                            Role = course.Teacher.User.Role,
                            ContactDetails = course.Teacher.User.ContactDetails
                        }
                    }
                }
            };

            return CreatedAtAction(nameof(GetAllBatches), new { id = batch.BatchId }, createdBatchDto);
        }



        // PUT: api/admin/batches/{id}
        [HttpPut("batches/{id}")]
        public async Task<IActionResult> UpdateBatch(int id, [FromBody] BatchDTO batchDto)
        {
            var batch = await _context.Batches.Include(b => b.Course).ThenInclude(c => c.Teacher).ThenInclude(t => t.User)
                .FirstOrDefaultAsync(b => b.BatchId == id);

            if (batch == null) return NotFound();

            // Update batch details
            batch.BatchName = batchDto.BatchName;
            batch.BatchTiming = batchDto.BatchTiming;
            batch.BatchType = batchDto.BatchType;

            // Check if the course exists, and update course and teacher data
            if (batchDto.Course != null)
            {
                var course = await _context.Courses.Include(c => c.Teacher).ThenInclude(t => t.User)
                    .FirstOrDefaultAsync(c => c.CourseId == batchDto.Course.CourseId);

                if (course != null)
                {
                    // Update course information
                    course.CourseName = batchDto.Course.CourseName;
                    course.Description = batchDto.Course.Description;

                    // Check if the teacher exists, and update teacher data
                    if (batchDto.Course.Teacher != null)
                    {
                        var teacher = await _context.Teachers.Include(t => t.User)
                            .FirstOrDefaultAsync(t => t.TeacherId == batchDto.Course.Teacher.TeacherId);

                        if (teacher != null)
                        {
                            // Update teacher information
                            teacher.SubjectSpecialization = batchDto.Course.Teacher.SubjectSpecialization;
                            teacher.User.Name = batchDto.Course.Teacher.User.Name;
                            teacher.User.Email = batchDto.Course.Teacher.User.Email;
                            teacher.User.ContactDetails = batchDto.Course.Teacher.User.ContactDetails;
                            teacher.User.Role = batchDto.Course.Teacher.User.Role;

                            _context.Update(teacher);
                        }
                        else
                        {
                            return BadRequest("Teacher does not exist.");
                        }
                    }

                    _context.Update(course);  // Update the course data
                }
                else
                {
                    return BadRequest("Course does not exist.");
                }
            }

            // Save changes
            await _context.SaveChangesAsync();
            return NoContent();
        }


        // DELETE: api/admin/batches/{id}
        [HttpDelete("batches/{id}")]
        public async Task<IActionResult> DeleteBatch(int id)
        {
            var batch = await _context.Batches.FindAsync(id);
            if (batch == null) return NotFound();

            _context.Batches.Remove(batch);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        #endregion

        #region Reporting

        // GET: api/admin/reports/students
        [HttpGet("reports/students")]
        public async Task<IActionResult> GetStudentReports()
        {
            // This is a simplified view of student reports, you can enhance it as per your requirement.
            var studentReports = await _context.Students
                .Select(s => new
                {
                    StudentId = s.StudentId,
                    UserName = s.User.Name,
                    BatchName = s.Batch.BatchName,
                    EnrolledCourses = _context.StudentCourses.Count(sc => sc.StudentId == s.StudentId)
                })
                .ToListAsync();

            return Ok(studentReports);
        }
        #endregion
    }
}

